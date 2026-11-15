#!/usr/bin/env node
// verify_offline.js - independent Node.js verifier for Canari log bundles.
//
// Written against docs/spec/append-only-log.md, NOT against canari Python.
// Only node:crypto and node:fs are used; there are no dependencies.
//
//   node docs/spec/verify_offline.js bundle.json [--log-id ID] [--root HEX] [--min-size N]
//
// Exit: 0 pass, 2 a check failed, 3 bad usage/unreadable.
"use strict";

const crypto = require("crypto");
const fs = require("fs");

const SPEC = "canari-append-only-log/v1";
const BUNDLE_SPEC = "canari-inclusion-bundle/v1";
const SIGN_PREFIX = Buffer.from("canari-tree-head/v1\u0000", "utf8");
const LEAF = Buffer.from([0x00]);
const NODE = Buffer.from([0x01]);

function sha(b) {
  return crypto.createHash("sha256").update(b).digest();
}

// Canonical JSON must match Python: sort_keys, separators (",", ":"),
// ensure_ascii=false. JSON.stringify with a sorted-key replacer is equivalent
// for the value types used here (no floats requiring repr differences).
function canonicalJSON(obj) {
  return Buffer.from(JSON.stringify(sortKeys(obj)), "utf8");
}

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortKeys(v[k]);
    return out;
  }
  return v;
}

function hexToBuf(h) {
  if (typeof h !== "string" || !/^[0-9a-fA-F]*$/.test(h)) return null;
  if (h.length % 2) return null;
  return Buffer.from(h, "hex");
}

function verifyInclusion(data, index, size, rootHex, proof) {
  if (!Number.isInteger(index) || !Number.isInteger(size)) return false;
  if (size <= 0 || index < 0 || index >= size) return false;
  if (size > 2 ** 40 || proof.length > 64) return false;
  let r = sha(Buffer.concat([LEAF, data]));
  let fn = index;
  let sn = size - 1;
  for (const p of proof) {
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) {
      r = sha(Buffer.concat([NODE, p, r]));
      while (!(fn & 1) && fn !== 0) {
        fn >>>= 1;
        sn >>>= 1;
      }
    } else {
      r = sha(Buffer.concat([NODE, r, p]));
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  return sn === 0 && r.toString("hex") === rootHex;
}

function verifyConsistency(first, second, firstRootHex, secondRootHex, proof) {
  if (!Number.isInteger(first) || !Number.isInteger(second)) return false;
  if (first < 0 || second < first || second > 2 ** 40 || proof.length > 64) {
    return false;
  }
  if (first === second) return proof.length === 0 && firstRootHex === secondRootHex;
  if (first === 0) return proof.length === 0;
  let fn = first - 1;
  let sn = second - 1;
  while (fn & 1) {
    fn >>>= 1;
    sn >>>= 1;
  }
  let fr, sr, rest;
  if (fn === 0) {
    const r = hexToBuf(firstRootHex);
    if (!r) return false;
    fr = sr = r;
    rest = proof;
  } else {
    if (proof.length === 0) return false;
    fr = sr = proof[0];
    rest = proof.slice(1);
  }
  for (const c of rest) {
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) {
      fr = sha(Buffer.concat([NODE, c, fr]));
      sr = sha(Buffer.concat([NODE, c, sr]));
      while (!(fn & 1) && fn !== 0) {
        fn >>>= 1;
        sn >>>= 1;
      }
    } else {
      sr = sha(Buffer.concat([NODE, sr, c]));
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  return sn === 0 && fr.toString("hex") === firstRootHex &&
         sr.toString("hex") === secondRootHex;
}

function verifyHeadSignature(head, key) {
  try {
    const body = head.body;
    if (!body || body.spec !== SPEC) return false;
    const sigHex = head.signature && head.signature.sig;
    const sig = hexToBuf(sigHex);
    if (!sig || sig.length !== 64) return false;
    const pubHex = key && key.keyval && key.keyval.public;
    const pub = hexToBuf(pubHex);
    if (!pub || pub.length !== 32) return false;
    if ((key.keytype || "ed25519") !== "ed25519") return false;
    // Raw Ed25519 verify: wrap the 32-byte public key in SPKI DER.
    const der = Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"), pub,
    ]);
    const keyObj = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    return crypto.verify(null, Buffer.concat([SIGN_PREFIX, canonicalJSON(body)]),
                         keyObj, sig);
  } catch (e) {
    return false;
  }
}

function validHeadBody(body, logId) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return "no body";
  if (body.spec !== SPEC) return "unsupported spec " + JSON.stringify(body.spec);
  if (logId !== null && body.log_id !== logId) return "log_id mismatch";
  const size = body.size;
  if (!Number.isInteger(size) || size < 0 || size > 2 ** 40) return "bad size";
  if (!hexToBuf(body.root) || body.root.length !== 64) return "bad root";
  if (typeof body.timestamp !== "string" || !body.timestamp) return "bad timestamp";
  return "";
}

function verifyBundle(bundle, opts = {}) {
  const checks = [];
  const add = (name, ok, detail = "") => {
    checks.push({ name, ok: !!ok, detail });
    return ok;
  };

  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    add("bundle.shape", false, "not a JSON object");
    return { ok: false, checks };
  }
  const logId = opts.logId === undefined ? null : opts.logId;
  add("bundle.spec", bundle.spec === BUNDLE_SPEC, "spec=" + JSON.stringify(bundle.spec));
  if (logId !== null) {
    add("log_id.pinned", bundle.log_id === logId,
        "bundle=" + JSON.stringify(bundle.log_id));
    if (bundle.log_id !== logId) {
      return { ok: false, checks, log_id: bundle.log_id };
    }
  }
  const key = bundle.public_key;
  if (!key || typeof key !== "object") {
    add("public_key.present", false, "missing");
    return { ok: false, checks };
  }
  add("public_key.present", true, "keyid=" + (key.keyid || "(none)"));

  const head = bundle.tree_head;
  if (!head || !head.body) {
    add("tree_head.present", false, "missing");
    return { ok: false, checks };
  }
  const body = head.body;
  const err = validHeadBody(body, bundle.log_id);
  add("tree_head.structure", err === "", err);
  add("tree_head.signature", verifyHeadSignature(head, key), "ed25519");

  const entry = bundle.entry || {};
  let data = null;
  try {
    data = Buffer.from(String(entry.data_b64 || ""), "base64");
    if (data.length === 0) data = null;
  } catch (e) {
    data = null;
  }
  add("entry.data_decodes", data !== null, data ? data.length + " bytes" : "unreadable");
  const proof = (bundle.inclusion_proof || []).map(hexToBuf);
  if (data !== null && proof.every(Boolean)) {
    add("entry.inclusion",
        verifyInclusion(data, entry.index, body.size, body.root, proof),
        "index=" + entry.index + " size=" + body.size);
  } else {
    add("entry.inclusion", false, "bad entry or proof encoding");
  }

  if (opts.root !== undefined && opts.root !== null) {
    add("root.pinned", body.root === opts.root, "expected=" + opts.root);
  }
  if (opts.minSize) {
    add("size.min", Number.isInteger(body.size) && body.size >= opts.minSize,
        "size=" + body.size + " min=" + opts.minSize);
  }

  const cons = bundle.consistency;
  if (cons) {
    const fh = cons.from_head || {};
    const fb = fh.body;
    const ferr = validHeadBody(fb, bundle.log_id);
    add("consistency.from_head_structure", ferr === "", ferr);
    add("consistency.from_head_signature", verifyHeadSignature(fh, key), "ed25519");
    const cproof = (cons.proof || []).map(hexToBuf);
    if (ferr === "" && cproof.every(Boolean)) {
      add("consistency.proof",
          verifyConsistency(fb.size, body.size, fb.root, body.root, cproof),
          "from=" + fb.size + " to=" + body.size);
    } else {
      add("consistency.proof", false, "bad proof encoding");
    }
  }
  if (opts.pinnedPrefix !== undefined && opts.pinnedPrefix !== null) {
    if (!cons) {
      add("prefix.pinned", false,
          "no consistency block, so a pinned earlier root cannot be shown to be a prefix");
    } else {
      const fh = cons.from_head || {};
      const fb = fh.body || {};
      const got = fb.root;
      add("prefix.pinned", got === opts.pinnedPrefix,
          "from_head.root=" + got + " pinned=" + opts.pinnedPrefix);
      if (got === opts.pinnedPrefix) {
        const cproof2 = (cons.proof || []).map(hexToBuf);
        const chainOk = validHeadBody(fb, bundle.log_id) === "" &&
          cproof2.every(Boolean) &&
          verifyConsistency(fb.size, body.size, fb.root, body.root, cproof2);
        add("prefix.chain", chainOk, "pinned root is a prefix of this head");
      }
    }
  }
  return { ok: checks.every(c => c.ok), checks, log_id: bundle.log_id,
           size: body.size, root: body.root };
}

function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0) {
    console.error("usage: node verify_offline.js bundle.json [--log-id ID] [--root HEX] [--min-size N]");
    return 3;
  }
  const opts = {};
  let file = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--log-id") opts.logId = args[++i];
    else if (a === "--root") opts.root = args[++i];
    else if (a === "--min-size") opts.minSize = parseInt(args[++i], 10);
    else if (a === "--pinned-prefix") opts.pinnedPrefix = args[++i];
    else if (a === "--json") opts.json = true;
    else if (file === null) file = a;
  }
  let bundle;
  try {
    bundle = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    console.error("cannot read bundle: " + e.message);
    return 3;
  }
  const rep = verifyBundle(bundle, opts);
  if (opts.json) {
    console.log(JSON.stringify(rep, null, 1));
  } else {
    for (const c of rep.checks) {
      console.log((c.ok ? "PASS " : "FAIL ") + c.name +
                  (c.detail ? "  (" + c.detail + ")" : ""));
    }
    console.log("RESULT: " + (rep.ok ? "OK" : "FAILED"));
  }
  return rep.ok ? 0 : 2;
}

if (require.main === module) {
  process.exit(main(process.argv));
}
module.exports = { verifyBundle, verifyInclusion, verifyConsistency, verifyHeadSignature };
