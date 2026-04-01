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

    def test_anonymize_scan_result_redacts_absolute_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            result = self.incident_scan.ScanResult(
                affected=True,
                affected_basis="assumed_compromise_due_to_uncertainty",
                confidence="Medium",
                evidence=[f"uncertainty:{root}/project:flag"],
                direct_compromise_evidence=[],
                uncertainty_evidence=[f"uncertainty:{root}/project:flag"],
                risk_level="Medium",
                impacted_projects=[
                    self.incident_scan.ProjectFinding(
                        root=str(root / "project"),
                        uncertainty_flags=[f"scan_error:{root}/project/package-lock.json"],
                    )
                ],
                direct_impacted_projects=[],
                uncertainty_impacted_projects=[],
                ci_pipelines_with_npm_install=[str(root / ".github" / "workflows" / "ci.yml")],
                probable_secret_exposures=[f"env_file_present:{root}/project/.env"],
                lateral_movement_paths=[f"path:{root}/project"],
                production_exposure_risk="Low",
                immediate_actions=[],
                remediation_plan=[],
                preventive_measures=[],
            )

            anon = self.incident_scan.anonymize_scan_result(result, [root])
            self.assertNotIn(str(root), json.dumps(self._as_json(anon)))
            self.assertIn("<SCAN_ROOT_1>", json.dumps(self._as_json(anon)))

    @staticmethod
    def _as_json(result):
        return {
            "evidence": result.evidence,
            "impacted_projects": [p.root for p in result.impacted_projects],
            "ci": result.ci_pipelines_with_npm_install,
            "secrets": result.probable_secret_exposures,
            "lateral": result.lateral_movement_paths,
        }


if __name__ == "__main__":
    unittest.main()
