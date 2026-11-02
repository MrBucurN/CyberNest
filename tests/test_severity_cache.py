import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestPersistentSeverityCache(unittest.TestCase):
    def test_concurrent_process_writes_are_atomic_and_preserve_entries(self):
        with tempfile.TemporaryDirectory(prefix="cybernest-cache-concurrency-") as directory:
            path = Path(directory) / "cache" / "cvss-cache-v1.json"
            worker = (
                "import sys,time; from cybernest.integrations.severity_cache import PersistentSeverityCache; "
                "PersistentSeverityCache(sys.argv[1],3600).put(sys.argv[2],"
                "{'severity':'HIGH','cvss_score':7.5,'cvss_vector':'vector','cvss_version':'3.1','source':'NVD'},now=time.time())"
            )
            children = [
                subprocess.Popen(
                    [sys.executable, "-c", worker, str(path), identifier],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for identifier in ("CVE-2026-10001", "CVE-2026-10002")
            ]
            outputs = [child.communicate(timeout=15) for child in children]

            self.assertTrue(all(child.returncode == 0 for child in children), outputs)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(set(payload["entries"]), {"CVE-2026-10001", "CVE-2026-10002"})
            self.assertFalse(list(path.parent.glob(".cvss-cache-*.tmp")))


if __name__ == "__main__":
    unittest.main()
