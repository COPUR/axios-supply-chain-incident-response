import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class IncidentScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.incident_scan = load_module("incident_scan_module", cls.repo_root / "scripts" / "incident_scan.py")

    def test_uncertainty_only_sets_assumed_compromise_basis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir(parents=True, exist_ok=True)
            (project / "package.json").write_text(
                json.dumps({"name": "p", "version": "1.0.0", "dependencies": {"axios": "^1.11.0"}}),
                encoding="utf-8",
            )

            result = self.incident_scan.run_scan([root])
            self.assertTrue(result.affected)
            self.assertEqual(result.affected_basis, "assumed_compromise_due_to_uncertainty")
            self.assertEqual(len(result.direct_compromise_evidence), 0)
            self.assertGreaterEqual(len(result.uncertainty_evidence), 1)

    def test_direct_malicious_lock_version_sets_direct_basis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir(parents=True, exist_ok=True)
            (project / "package.json").write_text(
                json.dumps({"name": "p", "version": "1.0.0", "dependencies": {"axios": "1.14.1"}}),
                encoding="utf-8",
            )
            lock = {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"axios": "1.14.1"}},
                    "node_modules/axios": {"name": "axios", "version": "1.14.1"},
                },
            }
            (project / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")

            result = self.incident_scan.run_scan([root])
            self.assertTrue(result.affected)
            self.assertEqual(result.affected_basis, "direct_compromise_detected")
            self.assertGreaterEqual(len(result.direct_compromise_evidence), 1)


if __name__ == "__main__":
    unittest.main()
