# Building the Android app

**Do this on a Mac, not on the homelab.** Not because of disk — the homelab has
78 GB free and the toolchain needs 10–12 GB — but because the app cannot be
*verified* there. Its entire reason to exist is hardware key custody, and
Keystore/StrongBox behaviour is only real on a physical device. An APK you
cannot run teaches you nothing. The homelab is also a 4-core box already
serving 52 pods, and Gradle would be competing with production for RAM.

## What is already done

| | |
|---|---|
| `crates/ffi` — uniffi bindings over the envelope core | ✅ 5 boundary tests |
| Generated Kotlin bindings | ✅ |
| **JVM conformance: all 22 vectors pass in Kotlin** | ✅ |
| `spec/vectors` | ✅ CLI, browser **and** Kotlin now agree byte for byte |

Run it with `just jvm-test`. It needs `kotlinc` and a JNA jar and nothing else —
no SDK, no NDK, no emulator, no device.

That means the format question is settled. Whatever remains is app work, not
interoperability work, and a file written on a phone will open on a laptop.

## What is left

1. Android SDK + NDK, and the four Rust Android targets
2. The app itself: Keystore custody, `FLAG_SECURE`, and Shred

Both need a Mac with a phone attached.

---

## Running the JVM conformance suite elsewhere

```bash
brew install kotlin                                     # kotlinc, ~70 MB
JNA_JAR=/path/to/jna-5.14.0.jar just jvm-test
```

Three things cost time to discover; they are baked into `run.sh` but are worth
knowing when it breaks on a new machine.

**Generate bindings from the DEBUG library, not the release one.** The
workspace release profile sets `strip = true`, which removes the metadata
symbols `uniffi-bindgen` reads. The failure is silent — bindgen exits 0 and
writes nothing — and with `--crate` it reports *"Crate sirna_ffi not found in
libsirna_ffi.so"* about a library that plainly contains it.

**JNA reads `jna.library.path`, not `java.library.path`.** Setting the latter
produces an `UnsatisfiedLinkError` that names the right file and the right
directory while still not finding it.

**An error field named `message` will not compile.** uniffi maps the error onto
a Kotlin exception and the field collides with `Throwable.message`. The field is
called `detail` for that reason — the suite caught it before any app code
existed, which is precisely what it is for.

## 1. Android toolchain

```bash
brew install --cask android-commandlinetools
sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;27.2.12479018"

rustup target add aarch64-linux-android armv7-linux-androideabi \
                  x86_64-linux-android i686-linux-android
cargo install cargo-ndk
```

Use the Gradle **wrapper** the project generates rather than a system Gradle.

```bash
cargo ndk -t arm64-v8a -t armeabi-v7a -o android/app/src/main/jniLibs build --release
```

## 2. The app

Four screens, described in the plan: compose (also a share-sheet target), the
owner's vault with a **Shred** button per message, the release approval prompt,
and the shred confirmation.

Things that are not optional:

- **`FLAG_SECURE`** on every activity that can show a message. It blocks the
  stock screenshot API and the recents thumbnail. It does not block a camera
  pointed at the screen, and the threat model says so.
- **The key never touches disk unwrapped.** Generate the content key, wrap it
  immediately with a Keystore key (`setIsStrongBoxBacked(true)` with a software
  fallback, `setUserAuthenticationRequired(true)`), store only the wrapped
  blob, and zero the raw bytes. `sealBytes` returns the raw key precisely so
  Kotlin can do this — Rust has nowhere safe to keep it, because the secure
  element is on the Kotlin side.
- **Shred is `KeyStore.deleteEntry(alias)`.** That is the whole feature. After
  it, the wrapped blob on disk is permanently undecryptable, enforced by the
  TEE rather than by the filesystem — which is why this works even against
  copies of the ciphertext you do not control.
- **Plaintext is never written to disk**, and is rendered from memory.

## Why not a Docker build environment

The original plan called for a containerised SDK+NDK so nothing landed on the
homelab's small root filesystem. That reasoning no longer applies now that the
build has moved to a Mac, where the SDK belongs in its usual place and a device
can actually be plugged in. Keep the container idea in reserve for CI.

## Handing off

Everything needed is committed. Clone the repo, run `cargo test -p sirna-ffi`
to confirm the Rust side is intact on the new machine, then start at step 1.

The one thing that cannot be rediscovered from the code is *why* the corpus
matters, so it is worth repeating: **a vector that Kotlin cannot reproduce
means the Android app will silently fail to open files that every other client
opens fine.** Do not skip step 1 to get to the app sooner.
