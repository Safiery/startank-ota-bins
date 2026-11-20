import json
from pathlib import Path
import shutil
import tempfile
import unittest

from check_ota import ROOT, VARIANTS, check_manifest


class PackageTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        shutil.copytree(ROOT / "startank", self.root / "startank")
        self.path = self.root / "manifest.json"
        self.manifest = json.loads((ROOT / "manifest.json").read_text())
        self.releases = self.manifest["products"][0]["releases"]

    def check(self):
        self.path.write_text(json.dumps(self.manifest))
        check_manifest(self.root)

    def test_current_packages(self):
        self.check()

    def test_requires_both_variants(self):
        self.releases.pop()
        with self.assertRaisesRegex(ValueError, "one fuel and one water"):
            self.check()

    def test_rejects_corrupt_package_bytes(self):
        path = self.root / VARIANTS["fuel"][0]
        with path.open("r+b") as package:
            package.write(b"XX")
        with self.assertRaisesRegex(ValueError, "ZIP checksum"):
            self.check()

    def test_swapped_packages_fail_even_with_updated_zip_metadata(self):
        by_variant = {release["variant"]: release for release in self.releases}
        fuel = by_variant["fuel"]
        water = by_variant["water"]
        shutil.copyfile(self.root / VARIANTS["water"][0], self.root / VARIANTS["fuel"][0])
        for field in ("sha256", "sizeBytes", "imageSizeBytes", "mcubootName"):
            fuel[field] = water[field]
        with self.assertRaisesRegex(ValueError, "different sensor variant"):
            self.check()

    def test_rejects_different_download_target(self):
        self.releases[0]["url"] = self.releases[1]["url"]
        with self.assertRaisesRegex(ValueError, "download URL"):
            self.check()

    def test_rejects_production_channel(self):
        self.manifest["channel"] = "production"
        with self.assertRaisesRegex(ValueError, "test-channel"):
            self.check()

    def test_rejects_unreadable_release_version(self):
        self.releases[0]["version"] = "latest"
        with self.assertRaisesRegex(ValueError, "invalid version"):
            self.check()
