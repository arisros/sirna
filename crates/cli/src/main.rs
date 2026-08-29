//! The Sirna command-line client.
//!
//! Useful on its own with no server, no browser and no phone: seal a file, hand
//! over 24 words through some other channel, and the ciphertext is inert litter
//! until those words show up.

use sirna_cli::{remote, vectors};

use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use qrcode::render::unicode;
use qrcode::QrCode;
use sirna_core::{
    open, open_with_passphrase, seal, seal_with_passphrase, SealOptions, SecretKey,
    CHUNK_LOG2_DEFAULT,
};

#[derive(Parser)]
#[command(
    name = "sirna",
    about = "Encrypt something so that destroying the key destroys every copy",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file or stdin into an envelope, and print the key once.
    Seal {
        /// Input file, or `-` for stdin.
        input: String,
        /// Output envelope. Defaults to `<input>.sirna`, or stdout for stdin.
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Seconds until the message expires. 0 means no expiry.
        #[arg(long, default_value_t = 0)]
        expire: u64,
        /// Plaintext chunk size as a power of two.
        #[arg(long, default_value_t = CHUNK_LOG2_DEFAULT)]
        chunk: u8,
        /// Also render the key as a QR code in the terminal.
        #[arg(long)]
        qr: bool,
        /// Derive the key from a passphrase instead of generating one.
        /// Weaker: a passphrase carries far less entropy than 256 random bits.
        #[arg(long, conflicts_with = "qr")]
        passphrase: Option<String>,
    },
    /// Decrypt an envelope using a mnemonic or a `sirna1:` URI.
    Open {
        input: PathBuf,
        /// The key. Accepts 24 words or a `sirna1:` URI.
        #[arg(
            short,
            long,
            conflicts_with = "passphrase",
            required_unless_present = "passphrase"
        )]
        key: Option<String>,
        /// Open an envelope that was sealed with `--passphrase`.
        #[arg(long)]
        passphrase: Option<String>,
        /// Where to write the plaintext. Defaults to stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Show what an envelope reveals without a key.
    Inspect { input: PathBuf },
    /// Generate a fresh key and print both encodings.
    Keygen {
        #[arg(long)]
        qr: bool,
    },
    /// Upload an envelope to a server. The key is never sent.
    Push {
        input: PathBuf,
        #[arg(long, env = "SIRNA_SERVER")]
        server: String,
        /// Seconds until the server drops it. Omit for the server default.
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Download an envelope. It can only be fetched once.
    Pull {
        id: String,
        #[arg(long, env = "SIRNA_SERVER")]
        server: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Generate or verify the cross-target test vectors.
    Vectors {
        #[command(subcommand)]
        action: VectorAction,
    },
}

#[derive(Subcommand)]
enum VectorAction {
    /// Regenerate the corpus. Output is deterministic.
    Generate {
        #[arg(long, default_value = "spec/vectors")]
        out: PathBuf,
    },
    /// Check the corpus against this build.
    Verify {
        #[arg(long, default_value = "spec/vectors")]
        dir: PathBuf,
    },
}

/// The CLI is the one place allowed to read the system clock. `core` never
/// does, so that it stays testable and usable under wasm32.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn render_qr(text: &str) -> Result<String> {
    let code = QrCode::new(text.as_bytes()).context("building QR code")?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

fn print_key(key: &SecretKey, qr: bool) -> Result<()> {
    let uri = key.to_uri();

    // Everything about the key goes to stderr, so `sirna seal - > out.sirna`
    // does the obvious thing without the key landing inside the output file.
    eprintln!();
    eprintln!("  Key — shown once, and it cannot be recovered:");
    eprintln!();
    for (i, chunk) in key
        .to_mnemonic()
        .split_whitespace()
        .collect::<Vec<_>>()
        .chunks(6)
        .enumerate()
    {
        eprintln!("    {:>2}.  {}", i * 6 + 1, chunk.join("  "));
    }
    eprintln!();
    eprintln!("    {uri}");
    if qr {
        eprintln!();
        eprint!("{}", render_qr(&uri)?);
    }
    eprintln!();
    eprintln!("  Send this through a different channel than the envelope.");
    eprintln!("  Anyone holding both can read the message.");
    eprintln!();
    Ok(())
}

fn read_input(path: &str) -> Result<(Vec<u8>, Option<String>)> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok((buf, None))
    } else {
        let p = PathBuf::from(path);
        let data = std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned());
        Ok((data, name))
    }
}

fn write_output(out: Option<PathBuf>, data: &[u8]) -> Result<()> {
    match out {
        Some(p) => {
            std::fs::write(&p, data).with_context(|| format!("writing {}", p.display()))?;
            eprintln!("  wrote {} ({} bytes)", p.display(), data.len());
        }
        None => std::io::stdout().write_all(data)?,
    }
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Seal {
            input,
            out,
            expire,
            chunk,
            qr,
            passphrase,
        } => {
            let (plaintext, filename) = read_input(&input)?;
            let now = now_unix();

            let opts = SealOptions {
                filename,
                expires_at: if expire == 0 { 0 } else { now + expire },
                chunk_log2: Some(chunk),
                ..Default::default()
            };

            let mut rng = rand::rngs::OsRng;
            let target =
                out.or_else(|| (input != "-").then(|| PathBuf::from(format!("{input}.sirna"))));

            match passphrase {
                Some(p) => {
                    let envelope = seal_with_passphrase(&plaintext, &p, &opts, &mut rng, now)
                        .map_err(|e| anyhow::anyhow!("sealing failed: {e}"))?;
                    write_output(target, &envelope)?;
                    eprintln!();
                    eprintln!("  Sealed with a passphrase. There is no key to hand over —");
                    eprintln!("  the reader needs the passphrase and nothing else.");
                    eprintln!();
                    eprintln!("  This is weaker than the default: a passphrase you invented");
                    eprintln!("  has far less entropy than 256 random bits, and Argon2id makes");
                    eprintln!("  guessing expensive rather than impossible.");
                    eprintln!();
                }
                None => {
                    let (envelope, key) = seal(&plaintext, &opts, &mut rng, now)
                        .map_err(|e| anyhow::anyhow!("sealing failed: {e}"))?;
                    write_output(target, &envelope)?;
                    print_key(&key, qr)?;
                }
            }
        }

        Command::Open {
            input,
            key,
            passphrase,
            out,
        } => {
            let envelope =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;

            // The numeric code is part of the cross-target contract, so it is
            // surfaced rather than swallowed into prose.
            let opened = match (key, passphrase) {
                (_, Some(p)) => open_with_passphrase(&envelope, &p, now_unix()),
                (Some(k), None) => {
                    let key = SecretKey::parse(&k).map_err(|e| anyhow::anyhow!("{e}"))?;
                    open(&envelope, &key, now_unix())
                }
                (None, None) => unreachable!("clap requires one of --key or --passphrase"),
            }
            .map_err(|e| anyhow::anyhow!("{e} (code {})", e.code()))?;

            if let Some(name) = &opened.meta.filename {
                eprintln!("  filename: {name}");
            }
            write_output(out, &opened.plaintext)?;
        }

        Command::Inspect { input } => {
            let envelope =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let header = sirna_core::Header::parse(&envelope)
                .map_err(|e| anyhow::anyhow!("{e} (code {})", e.code()))?;

            // Deliberately short. Filename, MIME type, true length and expiry
            // all live inside the encrypted metadata block — which is the
            // point: holding the ciphertext teaches you almost nothing.
            println!("format version : {}", sirna_core::FORMAT_VERSION);
            println!("chunk size     : {} bytes", header.chunk_size());
            println!(
                "kind           : {}",
                if header.is_file() { "file" } else { "text" }
            );
            println!("envelope size  : {} bytes", envelope.len());
            println!();
            println!("Everything else is encrypted, including the filename and expiry.");
        }

        Command::Keygen { qr } => {
            let mut rng = rand::rngs::OsRng;
            let key = SecretKey::generate(&mut rng);
            print_key(&key, qr)?;
        }

        Command::Push { input, server, ttl } => {
            let envelope =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let created = remote::push(&server, &envelope, ttl)?;

            // The id goes to stdout so it can be piped; everything else is
            // commentary and belongs on stderr.
            println!("{}", created.id);
            eprintln!("  delete token : {}", created.delete_token);
            eprintln!("  keep the delete token if you may want to withdraw this");
            eprintln!();
            eprintln!("  The server holds the envelope only. Send the key separately,");
            eprintln!("  and remember it can be fetched exactly once.");
        }

        Command::Pull { id, server, out } => {
            let envelope = remote::pull(&server, &id)?;
            write_output(out, &envelope)?;
        }

        Command::Vectors { action } => match action {
            VectorAction::Generate { out } => {
                let n = vectors::generate(&out)?;
                eprintln!("  generated {n} vectors into {}", out.display());
            }
            VectorAction::Verify { dir } => {
                let (passed, failed) = vectors::verify(&dir)?;
                eprintln!("  {passed} passed, {failed} failed");
                if failed > 0 {
                    bail!("{failed} vector(s) failed");
                }
            }
        },
    }

    Ok(())
}
