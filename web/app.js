// Sirna web client.
//
// Three rules shape everything here:
//
//   1. The key is generated in this tab, shown exactly once, and never sent
//      anywhere. It is not put in the URL, the title, or history — the
//      `example.com/#key` pattern is deliberately rejected, because a link that
//      contains its own key is one forward away from being useless.
//   2. Nothing is loaded from a third-party origin. Every external origin in a
//      page that handles keys is an exfiltration channel.
//   3. Errors never confirm whether a message existed.

import init, {
  sealBytes,
  openEnvelope,
  openEnvelopeWithPassphrase,
  inspect,
} from "./sirna_wasm.js";

const app = document.getElementById("app");
const nowUnix = () => BigInt(Math.floor(Date.now() / 1000));

const TTL_CHOICES = [
  ["1 hour", 3600],
  ["1 day", 86400],
  ["7 days", 604800],
];

const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== false) n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(kid));
  }
  return n;
};

const show = (...nodes) => {
  app.replaceChildren(...nodes);
};

// One sentence for every failure, chosen so that "already read", "expired" and
// "never existed" are indistinguishable — the API refuses to confirm which, and
// the UI must not undo that.
const UNAVAILABLE =
  "This message is not available. It may have been read already, expired, or never existed.";

function errorText(e) {
  const code = Number(e?.code ?? 0);
  switch (code) {
    case 5:
      return "That key does not open this message.";
    case 6:
      return "This file is incomplete — some of its data is missing.";
    case 7:
      return "This file has extra data appended to it.";
    case 9:
      return "This message has expired.";
    case 11:
    case 12:
      return "That key is not quite right — check for a typo.";
    default:
      return e?.message ?? "Something went wrong.";
  }
}

// ---------------------------------------------------------------- compose

function compose() {
  const text = el("textarea", {
    id: "msg",
    rows: 7,
    placeholder: "Write a message, or drop a file below.",
  });
  const file = el("input", { type: "file", id: "file" });
  const ttl = el(
    "select",
    { id: "ttl" },
    TTL_CHOICES.map(([label, secs]) =>
      el("option", { value: secs, selected: secs === 86400 }, label),
    ),
  );
  const status = el("p", { class: "status" });

  const submit = el(
    "button",
    {
      class: "primary",
      onclick: async () => {
        submit.disabled = true;
        status.textContent = "Encrypting…";
        try {
          await sealAndUpload({ text: text.value, file: file.files[0], ttl: Number(ttl.value) });
        } catch (e) {
          status.textContent = errorText(e);
          submit.disabled = false;
        }
      },
    },
    "Seal",
  );

  show(
    el("h1", {}, "Send something once"),
    el("div", { class: "card" }, text, el("label", { for: "file" }, "…or a file"), file),
    el("div", { class: "row" }, el("label", { for: "ttl" }, "Expires after"), ttl),
    submit,
    status,
    el(
      "p",
      { class: "note" },
      "The key is made here in your browser and never sent to the server. " +
        "You will see it once.",
    ),
  );
}

async function sealAndUpload({ text, file, ttl }) {
  let bytes, filename, mime;
  if (file) {
    bytes = new Uint8Array(await file.arrayBuffer());
    filename = file.name;
    mime = file.type || "application/octet-stream";
  } else {
    if (!text.trim()) throw { message: "Write something first." };
    bytes = new TextEncoder().encode(text);
  }

  const now = nowUnix();
  const sealed = sealBytes(bytes, filename, mime, now + BigInt(ttl), now);

  const res = await fetch(`/api/v1/blobs?ttl=${ttl}`, {
    method: "POST",
    headers: { "content-type": "application/octet-stream" },
    body: sealed.envelope,
  });
  if (!res.ok) {
    throw { message: res.status === 429 ? "Too many requests — wait a moment." : "Upload failed." };
  }
  const { id } = await res.json();

  sealedView({ id, mnemonic: sealed.mnemonic, uri: sealed.uri });
}

// ---------------------------------------------------------------- sealed

function sealedView({ id, mnemonic, uri }) {
  const link = `${location.origin}/m/${id}`;
  const words = mnemonic.split(/\s+/);

  const copy = (value, btn) => async () => {
    try {
      await navigator.clipboard.writeText(value);
      btn.textContent = "Copied";
      setTimeout(() => (btn.textContent = btn.dataset.label), 1500);
    } catch {
      btn.textContent = "Press ⌘/Ctrl+C";
    }
  };

  const copyKey = el("button", { "data-label": "Copy key" }, "Copy key");
  copyKey.addEventListener("click", copy(mnemonic, copyKey));
  const copyLink = el("button", { "data-label": "Copy link" }, "Copy link");
  copyLink.addEventListener("click", copy(link, copyLink));

  show(
    el("h1", {}, "Sealed"),
    el("div", { class: "card warn" }, el("strong", {}, "This key is shown once."), " ",
      "It cannot be recovered — not by you, not by us. If you lose it, the message is gone."),
    el("h2", {}, "The key"),
    el(
      "ol",
      { class: "words" },
      words.map((w) => el("li", {}, w)),
    ),
    el("p", { class: "uri" }, uri),
    el("h2", {}, "The link"),
    el("p", { class: "uri" }, link),
    el("div", { class: "row" }, copyKey, copyLink),
    el(
      "p",
      { class: "note" },
      "Send the link and the key through different channels. Anyone who has both can read it.",
    ),
    el(
      "button",
      {
        class: "primary",
        onclick: () => {
          // Deliberate confirmation, not a close button. The key is gone from
          // this page afterwards and there is no way back to it.
          if (confirm("Saved the key? It cannot be shown again.")) compose();
        },
      },
      "I have saved the key",
    ),
  );
}

// ---------------------------------------------------------------- read

function readView(id) {
  const keyInput = el("input", {
    type: "text",
    id: "key",
    autocomplete: "off",
    spellcheck: "false",
    placeholder: "Paste the 24 words, or a sirna1: key",
  });
  const status = el("p", { class: "status" });

  const openIt = el(
    "button",
    {
      class: "primary",
      onclick: async () => {
        openIt.disabled = true;
        status.textContent = "Fetching…";
        try {
          await fetchAndOpen(id, keyInput.value);
        } catch (e) {
          status.textContent = errorText(e);
          openIt.disabled = false;
        }
      },
    },
    "Open",
  );

  show(
    el("h1", {}, "A message is waiting"),
    el("div", { class: "card" }, keyInput),
    openIt,
    status,
    el(
      "p",
      { class: "note" },
      "The key came to you separately — it is not part of this link. " +
        "Opening this message uses it up — it is removed from the server the "
        + "moment you press Open, even if something goes wrong afterwards.",
    ),
  );
}

async function fetchAndOpen(id, key) {
  if (!key.trim()) throw { message: "Enter the key first." };

  const res = await fetch(`/api/v1/blobs/${id}`);
  if (!res.ok) throw { message: UNAVAILABLE };
  const envelope = new Uint8Array(await res.arrayBuffer());

  // Fail on a malformed envelope before asking the crypto to try, so the
  // message is about the file rather than about the key.
  inspect(envelope);

  const now = nowUnix();
  const opened = key.includes(" ") || key.startsWith("sirna1:")
    ? openEnvelope(envelope, key.trim(), now)
    : openEnvelopeWithPassphrase(envelope, key, now);

  openedView(opened);
}

function openedView(o) {
  const body = o.is_file
    ? fileResult(o)
    : el("pre", { class: "plaintext" }, new TextDecoder().decode(o.plaintext));

  show(
    el("h1", {}, "Opened"),
    body,
    el(
      "div",
      { class: "card done" },
      "This message has been removed from the server. Reloading will not bring it back, "
      + "and nobody else can open it.",
    ),
  );
}

function fileResult(o) {
  const blob = new Blob([o.plaintext], { type: o.mime || "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = el("a", { class: "primary", href: url, download: o.filename || "message" },
    `Download ${o.filename || "file"}`);
  // The object URL keeps the plaintext alive in memory; release it once the
  // download has started.
  a.addEventListener("click", () => setTimeout(() => URL.revokeObjectURL(url), 30_000));
  return el("div", { class: "card" }, a);
}

// ---------------------------------------------------------------- boot

document.getElementById("why-weaker")?.addEventListener("click", () => {
  document.getElementById("weaker-dialog").showModal();
});

await init();

const match = location.pathname.match(/^\/m\/([0-9a-f]{32})$/);
if (match) readView(match[1]);
else compose();
