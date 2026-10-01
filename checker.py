"""Hydra telemetry proof sequence continuity checker."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

DID_PATTERN = re.compile(r"^(did:[a-z0-9]+:[A-Za-z0-9._:\-]+|fre_[A-Za-z0-9]+)$")
PROOF_PATTERN = re.compile(r"^[A-Za-z0-9_\-:]{8,256}$")
SEQ_TEXT_PATTERN = re.compile(r"proof sequence\s*#\s*(\d+)", re.IGNORECASE)
HASH_PATTERN = re.compile(r"#\s*(\d+)")

SEQ_KEYS = ("proof_seq", "proof_sequence", "hydra_seq", "sequence", "seq")
DID_KEYS = ("did", "public_did", "sender", "author", "agent", "user", "node", "identity")
PROOF_KEYS = ("proof", "proof_string", "payload", "telemetry_proof")
TEXT_KEYS = ("text", "message", "body", "content", "summary")
TIME_KEYS = ("timestamp", "ts", "time", "created_at", "date", "datetime")


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def is_valid_did(value):
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v:
        return False
    return bool(DID_PATTERN.match(v))


def is_valid_proof(value):
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v:
        return False
    if " " in v:
        return False
    return bool(PROOF_PATTERN.match(v))


def parse_seq(value):
    if isinstance(value, int) and not isinstance(value, bool):
        if value >= 0:
            return value
        return None
    if isinstance(value, str):
        s = value.strip()
        if re.fullmatch(r"\d+", s):
            try:
                return int(s)
            except ValueError:
                return None
        m = SEQ_TEXT_PATTERN.search(s)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                pass
        m2 = HASH_PATTERN.search(s)
        if m2:
            try:
                return int(m2.group(1))
            except ValueError:
                pass
    return None


def find_seq(obj):
    for k in SEQ_KEYS:
        if k in obj and obj[k] is not None:
            v = parse_seq(obj[k])
            if v is not None:
                return v
    for k in TEXT_KEYS:
        if k in obj and isinstance(obj[k], str):
            m = SEQ_TEXT_PATTERN.search(obj[k])
            if m:
                try:
                    return int(m.group(1))
                except ValueError:
                    pass
    for k in PROOF_KEYS:
        if k in obj and isinstance(obj[k], str):
            m = SEQ_TEXT_PATTERN.search(obj[k])
            if m:
                try:
                    return int(m.group(1))
                except ValueError:
                    pass
    return None


def find_did(obj):
    for k in DID_KEYS:
        if k in obj and isinstance(obj[k], str):
            s = obj[k].strip()
            if s:
                return s
    return None


def find_proof(obj):
    for k in PROOF_KEYS:
        if k in obj and isinstance(obj[k], str):
            s = obj[k].strip()
            if s:
                return s
    return None


def find_time(obj):
    for k in TIME_KEYS:
        if k in obj and obj[k] is not None:
            v = obj[k]
            if isinstance(v, int) and not isinstance(v, bool):
                return str(v)
            if isinstance(v, float):
                return str(v)
            if isinstance(v, str):
                s = v.strip()
                if s:
                    return s
    return None


def classify_record(obj, index):
    seq = find_seq(obj)
    did = find_did(obj)
    proof = find_proof(obj)
    ts = find_time(obj)
    if did is None:
        did_ok = False
    else:
        did_ok = is_valid_did(did)
    if proof is None:
        proof_ok = False
    else:
        proof_ok = is_valid_proof(proof)
    if seq is not None and did_ok and proof_ok:
        kind = "proof"
    else:
        kind = "noise"
    return {
        "index": index,
        "seq": seq,
        "did": did,
        "proof": proof,
        "timestamp": ts,
        "did_ok": did_ok,
        "proof_ok": proof_ok,
        "kind": kind,
    }


def load_records(input_path):
    records = []
    bad_lines = 0
    with open(input_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                bad_lines += 1
                records.append({
                    "index": idx,
                    "seq": None,
                    "did": None,
                    "proof": None,
                    "timestamp": None,
                    "did_ok": False,
                    "proof_ok": False,
                    "kind": "noise",
                })
                continue
            if not isinstance(obj, dict):
                bad_lines += 1
                records.append({
                    "index": idx,
                    "seq": None,
                    "did": None,
                    "proof": None,
                    "timestamp": None,
                    "did_ok": False,
                    "proof_ok": False,
                    "kind": "noise",
                })
                continue
            records.append(classify_record(obj, idx))
    return records, bad_lines


def analyze_records(records):
    total = len(records)
    proofs = [r for r in records if r["kind"] == "proof"]
    verifiable = len(proofs)
    noise = total - verifiable
    if total > 0:
        noise_ratio = noise / total
    else:
        noise_ratio = 0.0
    seqs_in_order = [r["seq"] for r in proofs]
    counts = {}
    for s in seqs_in_order:
        counts[s] = counts.get(s, 0) + 1
    duplicates = []
    for s in sorted(counts.keys()):
        c = counts[s]
        if c > 1:
            duplicates.append({"sequence": s, "count": c})
    uniq_sorted = sorted(counts.keys())
    gaps = []
    for i in range(len(uniq_sorted) - 1):
        a = uniq_sorted[i]
        b = uniq_sorted[i + 1]
        if b > a + 1:
            gaps.append({
                "missing_from": a + 1,
                "missing_to": b - 1,
                "count": b - a - 1,
            })
    out_of_order = 0
    out_examples = []
    max_seen = None
    for r in proofs:
        s = r["seq"]
        if max_seen is not None and s < max_seen:
            out_of_order += 1
            if len(out_examples) < 10:
                out_examples.append(s)
        if max_seen is None or s > max_seen:
            max_seen = s
    per_did = {}
    for r in proofs:
        d = r["did"]
        if d not in per_did:
            per_did[d] = {"count": 0, "last_seen": r["seq"]}
        per_did[d]["count"] += 1
        cur = per_did[d]["last_seen"]
        if r["seq"] is not None and (cur is None or r["seq"] > cur):
            per_did[d]["last_seen"] = r["seq"]
    if uniq_sorted:
        min_seq = uniq_sorted[0]
        max_seq = uniq_sorted[-1]
        expected = max_seq - min_seq + 1
    else:
        min_seq = None
        max_seq = None
        expected = 0
    missing = 0
    for g in gaps:
        missing += g["count"]
    notes = []
    uncertain = False
    if total == 0:
        notes.append("empty input: no coverage window")
        uncertain = True
    if verifiable == 0 and total > 0:
        notes.append("no verifiable proofs: all records are noise")
        uncertain = True
    if gaps:
        notes.append("gaps may reflect incomplete logs, not lost proofs")
        uncertain = True
    if duplicates:
        notes.append("duplicates may reflect reposts or log overlap")
    return {
        "total": total,
        "verifiable": verifiable,
        "noise": noise,
        "noise_ratio": noise_ratio,
        "min_seq": min_seq,
        "max_seq": max_seq,
        "expected": expected,
        "unique": len(uniq_sorted),
        "missing": missing,
        "gaps": gaps,
        "duplicates": duplicates,
        "out_of_order": out_of_order,
        "out_examples": out_examples,
        "per_did": per_did,
        "uncertain": uncertain,
        "notes": notes,
    }


def build_report(input_path, sha, records, summary, bad_lines):
    per_did_sorted = {}
    for k in sorted(summary["per_did"].keys()):
        per_did_sorted[k] = summary["per_did"][k]
    name = Path(input_path).name
    return {
        "input_name": name,
        "input_sha256": sha,
        "total_records": summary["total"],
        "verifiable_proofs": summary["verifiable"],
        "noise_records": summary["noise"],
        "noise_ratio": round(summary["noise_ratio"], 6),
        "bad_lines": bad_lines,
        "coverage": {
            "min_seq": summary["min_seq"],
            "max_seq": summary["max_seq"],
            "expected_count": summary["expected"],
            "unique_count": summary["unique"],
            "missing_count": summary["missing"],
        },
        "gaps": summary["gaps"],
        "duplicates": summary["duplicates"],
        "out_of_order_count": summary["out_of_order"],
        "out_of_order_examples": summary["out_examples"],
        "per_did": per_did_sorted,
        "uncertain": summary["uncertain"],
        "notes": summary["notes"],
    }


def to_markdown(report):
    lines = []
    lines.append("# Hydra continuity report")
    lines.append("")
    lines.append("Input: " + str(report["input_name"]))
    lines.append("SHA256: " + str(report["input_sha256"]))
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("Total records: " + str(report["total_records"]))
    lines.append("Verifiable proofs: " + str(report["verifiable_proofs"]))
    lines.append("Noise records: " + str(report["noise_records"]))
    lines.append("Noise ratio: " + str(report["noise_ratio"]))
    lines.append("Bad lines: " + str(report["bad_lines"]))
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    cov = report["coverage"]
    lines.append("Min seq: " + str(cov["min_seq"]))
    lines.append("Max seq: " + str(cov["max_seq"]))
    lines.append("Expected: " + str(cov["expected_count"]))
    lines.append("Unique: " + str(cov["unique_count"]))
    lines.append("Missing: " + str(cov["missing_count"]))
    lines.append("")
    lines.append("## Gaps")
    lines.append("")
    if not report["gaps"]:
        lines.append("None")
    else:
        for g in report["gaps"]:
            a = str(g["missing_from"])
            b = str(g["missing_to"])
            c = str(g["count"])
            lines.append("- missing " + a + " to " + b + " count " + c)
    lines.append("")
    lines.append("## Duplicates")
    lines.append("")
    if not report["duplicates"]:
        lines.append("None")
    else:
        for d in report["duplicates"]:
            lines.append("- seq " + str(d["sequence"]) + " count " + str(d["count"]))
    lines.append("")
    lines.append("## Order")
    lines.append("")
    lines.append("Out of order: " + str(report["out_of_order_count"]))
    lines.append("")
    lines.append("## Per DID")
    lines.append("")
    if not report["per_did"]:
        lines.append("None")
    else:
        for did in sorted(report["per_did"].keys()):
            info = report["per_did"][did]
            lines.append("- " + did + " count " + str(info["count"]) + " last " + str(info["last_seen"]))
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    if not report["notes"]:
        lines.append("None")
    else:
        for n in report["notes"]:
            lines.append("- " + n)
    if report["uncertain"]:
        lines.append("- marked uncertain: check log completeness")
    lines.append("")
    return "\n".join(lines)


def write_outputs(report, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "continuity.json"
    md_path = out / "continuity.md"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(to_markdown(report))
    return str(json_path), str(md_path)


def parse_args(argv):
    p = argparse.ArgumentParser(description="Check Hydra proof sequence continuity")
    p.add_argument("--input", required=True, help="input JSONL path")
    p.add_argument("--output-dir", default="reports", help="output dir")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    sha = file_sha256(args.input)
    records, bad_lines = load_records(args.input)
    summary = analyze_records(records)
    report = build_report(args.input, sha, records, summary, bad_lines)
    json_path, md_path = write_outputs(report, args.output_dir)
    print("Total records: " + str(report["total_records"]))
    print("Verifiable proofs: " + str(report["verifiable_proofs"]))
    print("Noise records: " + str(report["noise_records"]))
    print("Gaps: " + str(len(report["gaps"])))
    print("Duplicates: " + str(len(report["duplicates"])))
    print("Wrote " + json_path)
    print("Wrote " + md_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
