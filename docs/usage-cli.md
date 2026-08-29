# Using the Sirna CLI

No server, no browser, no phone. Seal something, hand over the words through a
different channel, and the file is inert until those words show up.

## Seal a file

```bash
sirna seal report.pdf
```

Writes `report.pdf.sirna` and prints the key **once**:

```
  Key — shown once, and it cannot be recovered:

     1.  legal  winner  thank  year  wave  sausage
     7.  worth  useful  legal  will  rather  hollow
    13.  quantum  wisdom  humble  gadget  copper  clip
    19.  shrimp  motion  velvet  garden  liberty  moment

    sirna1:AWvB4dK...

  Send this through a different channel than the envelope.
  Anyone holding both can read the message.
```

The key goes to **stderr**, the envelope to the file. That means
`sirna seal - > out.sirna` does the obvious thing without the key ending up
inside the output.

There is no way to recover this key. Not from the file, not from us. If you
lose it, the contents are gone — that is the design, not a limitation.

## Open it

```bash
sirna open report.pdf.sirna --key "legal winner thank year ..." --out report.pdf
```

The `--key` flag accepts either encoding:

```bash
sirna open note.sirna --key "sirna1:AWvB4dK..."
```

With no `--out`, the plaintext goes to stdout, so it pipes:

```bash
sirna open secrets.sirna --key "$KEY" | jq .
```

## Text through a pipe

```bash
echo "meeting moved to 3pm" | sirna seal - > note.sirna
```

## Expiry

```bash
sirna seal invoice.pdf --expire 86400     # one day
```

Expiry is stored **inside** the encrypted envelope, not alongside it. A reader
who has the file and the key still cannot open it after the deadline, and no
server is involved in enforcing that.

## QR code for handing the key over in person

```bash
sirna keygen --qr
sirna seal photo.jpg --qr
```

Renders the `sirna1:` URI as a QR block in the terminal. The other person scans
it off your screen — the key never travels over any network.

## Inspect what a stranger can learn

```bash
sirna inspect report.pdf.sirna
```

```
format version : 1
chunk size     : 65536 bytes
kind           : file
envelope size  : 104883299 bytes

Everything else is encrypted, including the filename and expiry.
```

That is the whole of it. Filename, MIME type, true length, expiry and any note
are inside the encrypted metadata block. Someone holding the ciphertext learns
its rough size and nothing else.

## What the errors mean

The messages are deliberately distinct, because "your key is wrong" and "your
download is broken" should not look the same:

| Message | What actually happened |
|---|---|
| `wrong key, or the envelope has been altered` (5) | The key does not match, or someone modified the file |
| `envelope is incomplete — data is missing from the end` (6) | Truncated. Usually an interrupted download or copy |
| `unexpected data after the end of the envelope` (7) | Something was appended |
| `this message has expired` (9) | Past its expiry; the file is intact but will not open |
| `key checksum does not match — likely a typo` (12) | A mistyped or misread word. The key itself is probably fine — check the spelling |

The number is the canonical error code from `spec/ENVELOPE.md` §9, and it is
identical across every Sirna client.

## Test vectors

```bash
sirna vectors verify --dir spec/vectors     # check a build against the corpus
sirna vectors generate --out spec/vectors   # regenerate; output is deterministic
```

The corpus is what stops the CLI, the browser and the Android app from
disagreeing about the format. Regenerating should produce byte-identical files;
if it does not, the wire format moved and `just spec-lint` will say so.

## Chunk size

```bash
sirna seal big.iso --chunk 20     # 1 MiB chunks instead of the default 64 KiB
```

Rarely worth changing. Larger chunks mean slightly less overhead and more memory
per chunk. The valid range is 10 to 24.
