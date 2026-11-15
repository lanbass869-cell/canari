# -*- coding: utf-8 -*-
"""What we would send to participate@lists.witness-network.org.

The Witness Network's participation page says, in as many words, that
maintainers may ignore requests from AI agents and that human-to-human
communication is preferred. So this file is a DRAFT for the operator to send
from a human mailbox. Nothing here is auto-submitted, and no address is
invented: if the contact line were fabricated, the request would be worthless
to anyone reading it.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from canari import checkpoint as c2sp


def build():
    with open(os.path.join(ROOT, "docs", "log", "public_key.json"),
              encoding="utf-8") as f:
        pub = json.load(f)
    raw = bytes.fromhex(pub["key"]["keyval"]["public"])
    origin = "github.com/lanbass869-cell/canari/log"
    vk = c2sp.vkey(origin, c2sp.LOG_KEY_TYPE, raw)
    return origin, vk


def render(contact, contact_url):
    origin, vk = build()
    return """Subject: Log participation request (staging): %(origin)s

Hello,

I would like to have this transparency log added to the staging log list.

Origin line:
  %(origin)s

Public key (vkey, key type 0x01 Ed25519):
  %(vk)s

add-checkpoint rate:
  At most 24 times per day. The log is appended once daily by a scheduled job;
  it does not push on every request.

Log list:
  staging

Contact:
  %(contact)s
  %(contact_url)s

What the log records:
  It is an append-only Merkle log (RFC 9162 hashing) of public agent-component
  data. Two published evidence exports are committed daily, byte-for-byte:
  mcpcost's registry probe results (62,493 rows, CC BY 4.0) and ProtocolProbe's
  package/repository record checks (63,318 rows, CC BY 4.0). The log also
  commits to our own published verdict bundles so a retracted verdict is
  visible rather than silently replaced.

What it does NOT record:
  It does not claim any upstream statement is true. It commits to "this exact
  byte string, with this SHA-256, was published at this URL at this time".
  The spec lists the four things the proof cannot show:
  https://github.com/lanbass869-cell/canari/blob/main/docs/spec/append-only-log.md#9-what-this-does-not-prove

Current state:
  size 43, root 1af057f1a731767fb55b6ac30954507b663b8faf1b33b7e67e9ba531310b91aa
  checkpoint: https://lanbass869-cell.github.io/canari/log/checkpoint.txt
  independent verifier (Python + Node, no network):
  https://github.com/lanbass869-cell/canari/blob/main/docs/spec/verify_offline.js

Interoperability evidence:
  Our checkpoint/note/cosignature code passes another project's published
  test vectors (alexar76/histor, Go-generated), so the bytes should be what
  your witness expects. We have not been witnessed by anyone yet; being listed
  would be the first independent co-signature on this log, which is why we are
  asking rather than claiming it.

Expected load:
  One checkpoint per day, so the request volume is far below the staging
  profiles. If the log is approved and later abandoned, it stops being pushed
  and holds no state on your side beyond the last co-signature.

Thank you.
""" % {"origin": origin, "vk": vk, "contact": contact,
       "contact_url": contact_url}


if __name__ == "__main__":
    print(render("<your contact email>", "<your contact page or profile URL>"))
