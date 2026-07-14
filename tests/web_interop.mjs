import fs from "node:fs";
import vm from "node:vm";
import { webcrypto } from "node:crypto";

const input = JSON.parse(fs.readFileSync(0, "utf8"));
const html = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
const scriptStart = html.lastIndexOf("<script>");
const scriptEnd = html.indexOf("</script>", scriptStart);

if (scriptStart < 0 || scriptEnd < 0) {
  throw new Error("Could not locate the inline web application script.");
}

function makeElement(initial = {}) {
  const classes = new Set();
  return {
    value: "",
    type: "text",
    disabled: false,
    hidden: false,
    innerHTML: "",
    textContent: "",
    className: "",
    tabIndex: 0,
    attributes: {},
    classList: {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name),
      contains: name => classes.has(name),
    },
    focus() {},
    setAttribute(name, value) { this.attributes[name] = String(value); },
    querySelector() { return { style: {} }; },
    ...initial,
  };
}

const elements = new Map([
  ["enc-text", makeElement({ value: input.plaintext ?? "" })],
  ["enc-pass", makeElement({ value: input.passphrase ?? "", type: "password" })],
  ["enc-status", makeElement()],
  ["enc-output", makeElement()],
  ["enc-result", makeElement()],
  ["enc-btn", makeElement()],
]);

let randomCall = 0;
const deterministicRandom = [input.salt_b64, input.nonce_b64]
  .filter(Boolean)
  .map(value => Uint8Array.from(Buffer.from(value, "base64")));

const crypto = {
  subtle: webcrypto.subtle,
  getRandomValues(target) {
    const source = deterministicRandom[randomCall++];
    if (!source || source.length !== target.length) {
      throw new Error("Deterministic random input does not match the requested length.");
    }
    target.set(source);
    return target;
  },
};

const context = vm.createContext({
  crypto,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  ArrayBuffer,
  atob: value => Buffer.from(value, "base64").toString("binary"),
  btoa: value => Buffer.from(value, "binary").toString("base64"),
  argon2: {
    ArgonType: { Argon2id: 2 },
    async hash() {
      return { hash: Uint8Array.from(Buffer.from(input.key_b64, "base64")) };
    },
  },
  document: {
    activeElement: null,
    getElementById: id => elements.get(id) ?? makeElement(),
    querySelector: () => ({ addEventListener() {} }),
    querySelectorAll: () => [],
  },
  navigator: { clipboard: { writeText: async () => {} } },
  setTimeout,
});

vm.runInContext(html.slice(scriptStart + "<script>".length, scriptEnd), context);

if (input.mode === "browser-encrypt") {
  await vm.runInContext("doEncrypt()", context);
  process.stdout.write(elements.get("enc-result").value);
} else if (input.mode === "browser-decrypt") {
  context.inputBlob = input.blob;
  context.inputPassphrase = input.passphrase;
  const plaintext = await vm.runInContext("decrypt(inputBlob, inputPassphrase)", context);
  process.stdout.write(plaintext);
} else {
  throw new Error(`Unsupported interoperability mode: ${input.mode}`);
}
