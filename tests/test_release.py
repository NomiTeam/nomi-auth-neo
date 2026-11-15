"""Check release gates with real Git history and inspect both distribution formats."""

import importlib.util
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "release", Path(__file__).resolve().parents[1] / "scripts/release.py"
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.environment = dict(
            os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1"
        )
        self.command("init", "-b", "main")
        self.command("config", "user.name", "Release Test")
        self.command("config", "user.email", "release@example.invalid")
        (self.directory / "Cargo.toml").write_text('[package]\nversion="0.1.0"\n')
        self.command("add", "Cargo.toml")
        self.command("commit", "-m", "initial")
        self.command("update-ref", "refs/remotes/origin/main", "HEAD")

    def command(self, *arguments):
        return subprocess.check_output(
            ["git", *arguments],
            cwd=self.directory,
            env=self.environment,
            stderr=subprocess.STDOUT,
            text=True,
        ).strip()

    def test_main_annotated_and_lightweight_tags_are_allowed(self):
        for annotated in (False, True):
            with self.subTest(annotated=annotated):
                if annotated:
                    self.command("tag", "-f", "-a", "v0.1.0", "-m", "release")
                else:
                    self.command("tag", "v0.1.0")
                self.assertEqual(release.validate(self.directory, "v0.1.0"), "0.1.0")

    def test_unmerged_tag_is_rejected_even_with_matching_version(self):
        (self.directory / "dev.txt").write_text("unmerged")
        self.command("add", ".")
        self.command("commit", "-m", "unmerged")
        self.command("tag", "v0.1.0")
        with self.assertRaisesRegex(ValueError, "origin/main"):
            release.validate(self.directory, "v0.1.0")

    def test_wrong_tag_or_checkout_cannot_release_another_version(self):
        for tag in ("0.1.0", "v1.0.0", "prefix-v0.1.0", "v0.1.0\nextra"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.validate(self.directory, tag)
        self.command("tag", "v0.1.0")
        (self.directory / "next.txt").write_text("next")
        self.command("add", ".")
        self.command("commit", "-m", "next")
        with self.assertRaisesRegex(ValueError, "checkout"):
            release.validate(self.directory, "v0.1.0")

    def test_packages_exclude_real_configuration_and_keep_stable_binary_names(self):
        for name in (
            ".env.example",
            "README.md",
            "CONTRIBUTING.md",
            "API.md",
            "notices.md",
            "binary",
        ):
            (self.directory / name).write_text("example")
        (self.directory / ".env").write_text("must not ship")
        (self.directory / "deploy").mkdir()
        (self.directory / "deploy/nginx.conf").write_text("example")
        for platform in release.PLATFORMS:
            output = release.package(
                self.directory,
                self.directory / "binary",
                platform,
                self.directory / "notices.md",
                self.directory / "out",
            )
            if platform.startswith("windows"):
                with zipfile.ZipFile(output) as archive:
                    names = archive.namelist()
            else:
                with tarfile.open(output) as archive:
                    names = archive.getnames()
                    self.assertEqual(archive.getmember("nomi-auth-neo").mode, 0o755)
                    self.assertIn("deploy/nginx.conf", names)
            self.assertIn(release.PLATFORMS[platform], names)
            self.assertIn("THIRD_PARTY_NOTICES.md", names)
            self.assertIn(".env.example", names)
            self.assertIn("CONTRIBUTING.md", names)
            self.assertNotIn(".env", names)
            self.assertNotIn("Cargo.toml", names)


if __name__ == "__main__":
    unittest.main()
