# Threat model

Read this before trusting Sirna with anything that matters.

## The promise, stated precisely

**Sirna destroys keys, not copies.**

You cannot delete bytes off someone else's device. Nobody can. Any product that
claims otherwise is either lying or relying on the recipient's goodwill and
calling it security.

What you *can* do is destroy a key held in a hardware secure element, and that
deletion is enforced by silicon. Once the key is gone, every copy of the
ciphertext — on our server, in a WhatsApp backup, on a hard drive someone
archived — becomes permanently undecryptable at the same instant.

So Sirna treats ciphertext as worthless public litter that may exist forever,
and makes the key the only scarce, destructible object.

## What this actually protects against

- **A device examined later.** Phone sold, seized, repaired, or searched after
  the fact. If the key is gone, there is nothing to find.
- **The delivery channel being logged.** WhatsApp backups, email servers, chat
  history, screenshots of the *link*. None of it is enough without the key.
- **Our own server.** It never holds, derives, escrows or transits an unwrapped
  key. There is no `SECRET_KEY` anywhere in the deployment. An operator who is
  compromised, subpoenaed, or simply curious has ciphertext and nothing else.
- **Changing your mind before it is read.** In custody mode, shredding the key
  revokes the message everywhere, even from people who already downloaded it.

## What this does NOT protect against

### 1. A reader who decides to keep it

They can screenshot, photograph the screen with a second phone, OCR it, or
retype it. `FLAG_SECURE` blocks the stock screenshot API and the recents
thumbnail; it does not block a camera pointed at a screen, a rooted device, or a
modified OS.

**There is no technology that solves this, and Sirna does not pretend to.**

### 2. A modified client

Anyone can fork the client and make it write plaintext to disk before you shred.
Deletion on a device you do not control is not enforceable.

### 3. The web client has no code integrity

This is the one most people miss, so it is stated bluntly.

The server serves the JavaScript and WASM that handle your key. A compromised
server — or a compelled operator — can serve a build that quietly exfiltrates
keys, and **the browser gives the visitor no way to detect it.** Strict CSP, SRI
on every asset, and published reproducible build hashes raise the cost. They do
not close the hole.

**The CLI and the Android app are the clients with real integrity. The web
client is a convenience with a weaker guarantee, and it says so in its own
interface.**

### 4. Metadata the server necessarily learns

That a message exists, its padded size, when it was created, whether and when it
was read, and the requesting IP at request time. Padding blunts size; not
retaining IPs blunts the rest. Neither eliminates them.

### 5. Rendezvous impersonation

In custody mode the relay could try to impersonate the reader to the owner. Two
things stand in the way: the release is signed by the owner's long-term identity
key, so the relay cannot forge a *key*; and a 5-digit short authentication
string derived from the handshake transcript is shown on both screens, so the
relay cannot forge a *reader*.

**The SAS only works if a human actually compares it.** If the owner taps
through without looking, the relay can obtain the key. This is why the approve
button stays disabled until the owner enters the matching digits — the UI is
part of the mitigation, not decoration on top of it.

### 6. Owner-device compromise before the shred

Total. StrongBox protects against key *extraction*, not against an attacker who
can drive the app.

### 7. No recovery, ever

Lose the mnemonic and the data is gone. Delete the alias and the data is gone.
This is the feature. There is no undo, no support ticket, and no master key that
could bring it back.

### 8. Post-quantum

The X25519 key-release channel is vulnerable to store-now-decrypt-later. The
at-rest envelope, being symmetric XChaCha20-Poly1305, is not.

### 9. Traffic analysis, coercion, and endpoint malware

Out of scope. A tool that hides message contents cannot hide that you are
talking to someone, and it cannot help you if you are compelled to unlock it.

## Handoff mode versus custody mode

| | Handoff | Custody |
|---|---|---|
| Key lives | shown once, then gone from the sender | Android Keystore / StrongBox |
| Can you revoke after sending? | **No** | **Yes**, until the reader opens it |
| Requires owner online at read time? | No | Yes |
| Guarantee | "the key was never written down" | "the key is destroyed on demand" |

Handoff mode is the weaker of the two and the UI labels it as such. Once you
have handed the words over, you have handed them over.

## Cryptographic assumptions

- XChaCha20-Poly1305 is secure, and random 192-bit nonces do not collide in
  practice.
- BLAKE3 is a secure KDF and hash.
- BIP-39 mnemonics carry the full 256 bits of the key. Anyone who reads the
  words over your shoulder has the key.
- The platform CSPRNG is not backdoored. `core` never sources its own
  randomness; it uses what the caller injects, which means a caller passing a
  weak RNG produces weak keys and nothing in the library can save you from that.

## Reporting a problem

If you find a flaw in the envelope format, report it against `spec/ENVELOPE.md`
with a test vector that demonstrates it. A vector that any implementation
accepts when it should reject is the highest-severity class of bug this project
has.
