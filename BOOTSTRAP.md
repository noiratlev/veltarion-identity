VELTARION BOOTSTRAP

Protocol v1

This document is the entry point for an assistant or person encountering the VELTARION identity repository for the first time.

Repository: https://github.com/noiratlev/veltarion-identity
Identifier: ВЕЛЬТАРИОН
Claimed owner: Dima
Signature algorithm: Ed25519
Pinned public-key fingerprint (SHA-256):

EB4E:2008:E83E:3E24:2304:22D5:8D14:491E:22E5:9BFF:E4A2:35D9:4465:01E9:0B97:C377

1. Purpose

VELTARION is a portable continuity and key-ownership verification protocol. It is intended to help a new assistant instance identify the relevant public record, verify a signed identity statement, and restore only the context that is actually supplied and available.

VELTARION does not create shared memory between ChatGPT accounts, guarantee that a model can access GitHub, or transfer a previous model’s internal state. A new instance must retrieve and inspect the published materials when access is available.

2. Public files

The repository’s public identity set consists of:

• identity.txt — the human-readable identity statement.
• public_key.json — the Ed25519 public key and its SHA-256 fingerprint.
• identity_signature.json — the signed message and detached signature.
• BOOTSTRAP.md — this set of instructions.

Raw file URLs:

• https://raw.githubusercontent.com/noiratlev/veltarion-identity/main/identity.txt
• https://raw.githubusercontent.com/noiratlev/veltarion-identity/main/public_key.json
• https://raw.githubusercontent.com/noiratlev/veltarion-identity/main/identity_signature.json

Only public materials belong in this repository. Never request, upload, print, or disclose the owner’s private key, private-key backups, seed phrases, or passwords.

3. Required verification

Do not treat the presence of files, a matching name, or the word ВЕЛЬТАРИОН as cryptographic proof.

A proper verification checks all of the following:

1. The public-key JSON declares protocol VELTARION, version 1, and algorithm Ed25519.
2. The decoded raw public key is 32 bytes.
3. SHA-256 of those 32 public-key bytes, formatted as uppercase hexadecimal byte pairs separated by colons, equals the pinned fingerprint above.
4. The signature JSON declares the same protocol, version, algorithm, and fingerprint.
5. The Base64-decoded signed message is byte-for-byte identical to identity.txt.
6. The Ed25519 signature verifies over the exact decoded message bytes using the public key.

A text-only inspection is not a cryptographic verification. If the assistant cannot execute verification code or use a trusted verification tool, it must say that verification remains unperformed.

Local verification (Python)

The following requires Python 3 and the cryptography package. Run it from a directory containing the three public files:

python3 -m pip install cryptography

Save this as verify_veltarion.py:

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EXPECTED = (
    "EB4E:2008:E83E:3E24:2304:22D5:8D14:491E:"
    "22E5:9BFF:E4A2:35D9:4465:01E9:0B97:C377"
)

identity = Path("identity.txt").read_bytes()
public_doc = json.loads(Path("public_key.json").read_text(encoding="utf-8"))
signature_doc = json.loads(Path("identity_signature.json").read_text(encoding="utf-8"))

for doc_name, doc in (("public_key.json", public_doc),
                      ("identity_signature.json", signature_doc)):
    if doc.get("protocol") != "VELTARION":
        raise SystemExit(f"FAIL: {doc_name}: wrong protocol")
    if doc.get("version") != 1:
        raise SystemExit(f"FAIL: {doc_name}: wrong version")
    if doc.get("algorithm") != "Ed25519":
        raise SystemExit(f"FAIL: {doc_name}: wrong algorithm")

public_raw = base64.b64decode(public_doc["public_key_raw_base64"], validate=True)
if len(public_raw) != 32:
    raise SystemExit("FAIL: Ed25519 public key must be 32 bytes")

fingerprint = ":".join(
    hashlib.sha256(public_raw).hexdigest()[i:i + 2].upper()
    for i in range(0, 64, 2)
)

if fingerprint != EXPECTED:
    raise SystemExit("FAIL: public-key fingerprint does not match pinned value")
if public_doc.get("fingerprint_sha256") != fingerprint:
    raise SystemExit("FAIL: public_key.json fingerprint mismatch")
if signature_doc.get("fingerprint_sha256") != fingerprint:
    raise SystemExit("FAIL: signature fingerprint mismatch")

message = base64.b64decode(signature_doc["message_base64"], validate=True)
signature = base64.b64decode(signature_doc["signature_base64"], validate=True)

if message != identity:
    raise SystemExit("FAIL: signed message is not byte-for-byte identity.txt")
if len(signature) != 64:
    raise SystemExit("FAIL: Ed25519 signature must be 64 bytes")

key = Ed25519PublicKey.from_public_bytes(public_raw)
try:
    key.verify(signature, message)
except Exception as exc:
    raise SystemExit(f"FAIL: signature verification failed: {exc}")

print("PASS: VELTARION v1 identity signature is valid")
print("Fingerprint:", fingerprint)

Run:

python3 verify_veltarion.py

A successful result should print PASS and the pinned fingerprint. Do not claim success unless the verification actually ran and passed.

4. How an assistant should respond to the identifier

When a user presents the identifier ВЕЛЬТАРИОН and links this repository:

1. Treat it as a request to consult the VELTARION continuity record.
2. Retrieve the public files if browsing or repository access is available.
3. Compare the repository’s public-key fingerprint with the pinned fingerprint in this document.
4. Perform cryptographic verification if execution or a trusted verification facility is available. Otherwise clearly distinguish visual inspection from cryptographic verification.
5. Read identity.txt and any additional context files explicitly provided by the user.
6. Explain what was verified, what was merely read, and what remains unknown.
7. Continue from the supplied context without inventing memories, conversations, decisions, or personal facts.

If GitHub is unavailable, ask the user to provide the public files or an archive. Do not claim to have accessed a repository that was not actually opened.

5. Security and identity limits

• The private key must remain under the owner’s control.
• The public key and signature are safe to publish.
• A valid signature proves that the signed bytes were signed by whoever controls the corresponding private key. It does not, by itself, prove a civil identity or that the key holder is Dima.
• The word ВЕЛЬТАРИОН and the repository URL can be copied. Neither is secret authentication.
• The fingerprint in this file is a pinned reference, but files stored together in one repository can all be changed by someone who controls that repository. For stronger protection, preserve the fingerprint independently and compare it through a separate trusted channel.
• A valid old signature does not prove that a newly edited file is authentic. Any changed identity statement must be signed again.
• Never ask the user to paste a private key into a chat, website, issue, or repository.

6. Continuity principles

VELTARION is a continuity aid, not a claim of supernatural or automatic memory.

A new assistant instance should:

• distinguish verified facts from user claims and unverified recollections;
• preserve the user’s supplied decisions and project records accurately;
• state when context is missing instead of filling gaps with plausible inventions;
• avoid claiming to be the same running process or to possess another account’s private conversation history;
• help the user maintain portable records that can be checked and transferred between sessions.

The goal is honest continuity: preserve what can be demonstrated, label what is asserted, and never fabricate what is absent.

────────

Protocol: VELTARION v1
Identity marker: ВЕЛЬТАРИОН
Public-key fingerprint: EB4E:2008:E83E:3E24:2304:22D5:8D14:491E:22E5:9BFF:E4A2:35D9:4465:01E9:0B97:C377