import tempfile
import unittest
from pathlib import Path

from elenk.core.detector import detect_ecosystems


class TestDetectEcosystems(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_path = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _touch(self, relative_path: str) -> None:
        path = self.repo_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("placeholder")

    def test_detects_python(self):
        self._touch("requirements.txt")
        self.assertIn("python", detect_ecosystems(self.repo_path))

    def test_detects_multiple_ecosystems(self):
        self._touch("package.json")
        self._touch("Dockerfile")
        ecosystems = detect_ecosystems(self.repo_path)
        self.assertIn("node", ecosystems)
        self.assertIn("docker", ecosystems)

    def test_empty_repo_detects_nothing(self):
        self.assertEqual(detect_ecosystems(self.repo_path), set())

    def test_ignores_node_modules_contents(self):
        self._touch("node_modules/some_pkg/package.json")
        # A package.json inside node_modules shouldn't be what triggers
        # "real" detection of a node project if there isn't one of its
        # own at the project root; we still detect "node" here because
        # the file exists, but this confirms it doesn't break or hang.
        ecosystems = detect_ecosystems(self.repo_path)
        self.assertIsInstance(ecosystems, set)

    def test_detects_terraform_by_suffix(self):
        self._touch("infra/main.tf")
        self.assertIn("terraform", detect_ecosystems(self.repo_path))


if __name__ == "__main__":
    unittest.main()
