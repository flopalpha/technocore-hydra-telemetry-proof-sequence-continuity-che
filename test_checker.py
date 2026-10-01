import json
import tempfile
import unittest
from pathlib import Path
import checker


class TestContinuity(unittest.TestCase):
    def test_did_ok(self):
        self.assertTrue(checker.is_valid_did("did:technocore:nodeA1"))
        self.assertTrue(checker.is_valid_did("fre_0019"))
        self.assertFalse(checker.is_valid_did(""))
        self.assertFalse(checker.is_valid_did("not a did!"))
        self.assertFalse(checker.is_valid_did(None))

    def test_proof_ok(self):
        self.assertTrue(checker.is_valid_proof("hydra:27014:a1b2c3d4e5f6a1b2"))
        self.assertTrue(checker.is_valid_proof("a1b2c3d4e5f6a1b2c3d4"))
        self.assertFalse(checker.is_valid_proof("Technocore layer online"))
        self.assertFalse(checker.is_valid_proof("short"))
        self.assertFalse(checker.is_valid_proof(None))

    def test_seq_from_text(self):
        obj = {"text": "Hydra telemetry proof sequence #27014 verified"}
        self.assertEqual(checker.find_seq(obj), 27014)
        self.assertEqual(checker.parse_seq(27014), 27014)
        self.assertEqual(checker.parse_seq("27015"), 27015)
        self.assertIsNone(checker.parse_seq("hello"))

    def test_gap_list(self):
        recs = [
            checker.classify_record({"seq": 1, "did": "did:tc:n1", "proof": "hydra:00001:abcd1234efgh5678"}, 0),
            checker.classify_record({"seq": 2, "did": "did:tc:n1", "proof": "hydra:00002:abcd1234efgh5679"}, 1),
            checker.classify_record({"seq": 5, "did": "did:tc:n1", "proof": "hydra:00005:abcd1234efgh5680"}, 2),
        ]
        s = checker.analyze_records(recs)
        self.assertEqual(len(s["gaps"]), 1)
        self.assertEqual(s["gaps"][0]["missing_from"], 3)
        self.assertEqual(s["gaps"][0]["missing_to"], 4)
        self.assertEqual(s["gaps"][0]["count"], 2)

    def test_duplicates_and_order(self):
        recs = [
            checker.classify_record({"seq": 10, "did": "did:tc:n1", "proof": "hydra:00010:abcd1234efgh1111"}, 0),
            checker.classify_record({"seq": 11, "did": "did:tc:n1", "proof": "hydra:00011:abcd1234efgh2222"}, 1),
            checker.classify_record({"seq": 11, "did": "did:tc:n1", "proof": "hydra:00011:abcd1234efgh2222"}, 2),
            checker.classify_record({"seq": 9, "did": "did:tc:n2", "proof": "hydra:00009:abcd1234efgh3333"}, 3),
        ]
        s = checker.analyze_records(recs)
        self.assertEqual(len(s["duplicates"]), 1)
        self.assertEqual(s["duplicates"][0]["sequence"], 11)
        self.assertEqual(s["out_of_order"], 1)
        self.assertIn("did:tc:n1", s["per_did"])
        self.assertEqual(s["per_did"]["did:tc:n1"]["count"], 3)

    def test_noise_ratio(self):
        recs = [
            checker.classify_record({"seq": 27014, "did": "did:tc:n1", "proof": "hydra:27014:a1b2c3d4e5f6a1b2"}, 0),
            checker.classify_record({"text": "Technocore layer online"}, 1),
            checker.classify_record({"text": "hello", "sender": "fre_0019"}, 2),
        ]
        s = checker.analyze_records(recs)
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["verifiable"], 1)
        self.assertEqual(s["noise"], 2)

    def test_reports_are_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            inp = td_path / "in.jsonl"
            lines = [
                {"seq": 27014, "did": "did:tc:n1", "proof": "hydra:27014:a1b2c3d4e5f6a1b2"},
                {"text": "generic heartbeat"},
            ]
            with open(inp, "w", encoding="utf-8") as f:
                for obj in lines:
                    f.write(json.dumps(obj) + "\n")
            out = td_path / "out"
            sha = checker.file_sha256(str(inp))
            recs, bad = checker.load_records(str(inp))
            summary = checker.analyze_records(recs)
            report = checker.build_report(str(inp), sha, recs, summary, bad)
            p1, p2 = checker.write_outputs(report, str(out))
            self.assertTrue(Path(p1).exists())
            self.assertTrue(Path(p2).exists())
            with open(p1, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["input_sha256"], sha)
            self.assertEqual(data["total_records"], 2)
            with open(p2, "r", encoding="utf-8") as f:
                text = f.read()
            self.assertIn("Hydra continuity", text)

    def test_cli_main(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            inp = td_path / "room.jsonl"
            with open(inp, "w", encoding="utf-8") as f:
                f.write(json.dumps({"seq": 7, "did": "fre_0019", "proof": "hydra:00007:abcd1234efgh9999"}) + "\n")
                f.write(json.dumps({"text": "noise here"}) + "\n")
                f.write("not json {\n")
            out = td_path / "reports"
            code = checker.main(["--input", str(inp), "--output-dir", str(out)])
            self.assertEqual(code, 0)
            self.assertTrue((out / "continuity.json").exists())
            self.assertTrue((out / "continuity.md").exists())


if __name__ == "__main__":
    unittest.main()
