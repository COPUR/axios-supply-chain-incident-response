import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


def load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class GuardrailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.guardrail_script = cls.repo_root / "scripts" / "guardrail.py"
        cls.guardrail = load_module("guardrail_module", cls.guardrail_script)

    def test_extract_direct_packages_from_lock_v2(self):
        lock_data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"axios": "1.14.1", "chalk": "5.3.0"}},
                "node_modules/axios": {"version": "1.14.1"},
                "node_modules/chalk": {"version": "5.3.0"},
                "node_modules/ansi-styles": {"version": "6.2.1"},
            },
        }

        direct = self.guardrail.extract_direct_packages_from_lock(lock_data)
        self.assertIn(("axios", "1.14.1"), direct)
        self.assertIn(("chalk", "5.3.0"), direct)
        self.assertNotIn(("ansi-styles", "6.2.1"), direct)

    def test_denylist_only_blocks_malicious_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            lock_data = {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"axios": "1.14.1", "safe-lib": "1.0.0"}},
                    "node_modules/axios": {"version": "1.14.1"},
                    "node_modules/safe-lib": {"version": "1.0.0"},
                },
            }
            (tmp_path / "package-lock.json").write_text(json.dumps(lock_data), encoding="utf-8")

            policy = {
                "min_package_age_hours": 48,
                "strict_mode": True,
                "denylist": {"axios": ["1.14.1", "0.30.4"], "plain-crypto-js": ["4.2.1"]},
                "allowlist": [],
            }
            policy_path = tmp_path / "guardrail-policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")

            result_path = tmp_path / "guardrail-result.json"
            env = os.environ.copy()
            env["GUARDRAIL_POLICY_FILE"] = str(policy_path)
            env["GUARDRAIL_RESULT_FILE"] = str(result_path)
            env["GUARDRAIL_DENYLIST_ONLY"] = "1"

            proc = subprocess.run(
                ["python3", str(self.guardrail_script)],
                cwd=str(tmp_path),
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)

            result = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "block")
            self.assertEqual(result["mode"], "denylist_only")
            self.assertGreaterEqual(result["summary"]["blocked_count"], 1)


if __name__ == "__main__":
    unittest.main()
