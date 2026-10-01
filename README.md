Hydra Telemetry Proof Sequence Continuity Checker

Public-data observability helper for Technocore room exports.
The sampled room is flooded with generic heartbeats, DID-active claims,
Ed25519-verified notes with no payload, and fre_ check-ins. Against that
noise there is a single Hydra telemetry proof sequence with no continuity
context. This tool separates verifiable sequenced proofs from noise and
reports gaps, duplicates, and per-DID continuity.

What it does

- Reads a public room JSONL export, one JSON object per line.
- Extracts Hydra proof sequence numbers, timestamps, and public DIDs.
- Checks public proof-string shape and DID shape only, no private data.
- Finds missing, duplicate, and out-of-order sequence numbers.
- Counts per-DID proofs and last-seen sequence.
- Reports noise ratio: sequenced proofs vs generic presence heartbeats.
- Checksums the input file and writes reproducible JSON + Markdown reports.
- Offline only, deterministic output, standard library only.

Install

No extra packages. Needs Python 3.9 or later.

Clone or copy this folder, then run:

  python checker.py --help

Input format

JSONL, one JSON object per line. Blank lines are skipped.
Flexible keys are accepted:

- sequence: proof_seq, proof_sequence, hydra_seq, sequence, seq,
  or text like "Hydra telemetry proof sequence #27014"
- DID: did, public_did, sender, author, agent, user, node, identity
- proof string: proof, proof_string, payload, telemetry_proof
- time: timestamp, ts, time, created_at, date, datetime
- text: text, message, body, content, summary

A record counts as a verifiable proof only when it has:

- a sequence number, plus
- a DID matching did:method:name or fre_0019 style, plus
- a proof string of 8-256 chars from A-Z a-z 0-9 _ - : with no spaces

Example: "hydra:27014:a1b2c3d4e5f6a1b2" is valid.
Example: "Technocore layer online" is noise because it has spaces.

Everything else counts as noise. Bad JSON lines also count as noise
and are listed in the report.

Usage

  python checker.py --input sample.jsonl --output-dir reports

Output is written to:

- reports/continuity.json
- reports/continuity.md

The JSON report holds input name, sha256, totals, coverage window,
gap list, duplicate list, out-of-order count, per-DID table, and notes.
The Markdown report holds the same data in readable form.

Example run

  python checker.py --input sample.jsonl --output-dir reports
  Total records: 8
  Verifiable proofs: 4
  Noise records: 4

See sample.jsonl for a small mixed export with a gap and a duplicate.

Limits

- Read-only helper for public exports. It never reads private keys or seeds.
- It never posts, claims tokens, or uses the network.
- A gap may mean an incomplete log, not a lost proof. The report checksums
  the input, shows the coverage window, and marks uncertain cases.
- Timestamp handling is simple string passthrough; ordering uses sequence.

Safety

- Only the Python standard library is used.
- Only reads the file given by --input and writes to --output-dir.
- No private data, no posting, no network calls.
