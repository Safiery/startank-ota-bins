import hashlib
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from zipfile import ZipFile

from check_ota import KNOWN_IMAGES, ROOT, VARIANTS, check_image, check_manifest, version_key


def inert_image(version=(0, 0, 0, 0), address=0, protected=b""):
    body = b"inert fixture data"
    header = struct.pack("<IIHHIIBBHII", 0x96F3B83D, address, 32, len(protected),
                         len(body), 0, *version, 0)
    signed = header + body + protected
    return signed + struct.pack("<HHHH", 0x6907, 40, 0x10, 32) + hashlib.sha256(signed).digest()


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
        return check_manifest(self.root)

    def test_current_packages(self):
        self.assertEqual(self.check(), {variant: digest for digest, variant in KNOWN_IMAGES.items()})

    def replace_fuel_image(self, image):
        path = self.root / VARIANTS["fuel"][0]
        with ZipFile(path) as archive:
            inner = json.loads(archive.read("manifest.json"))
        inner["files"][0]["size"] = len(image)
        with ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", json.dumps(inner))
            archive.writestr("app_update.bin", image)
        fuel = next(r for r in self.releases if r["variant"] == "fuel")
        fuel.update(imageSizeBytes=len(image), sizeBytes=path.stat().st_size,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    def test_embedded_image_checked_even_if_outer_checksum_matches(self):
        for data, reason in (
            (inert_image(version=(1, 2, 3, 4)), "header version"),
            (inert_image(address=1234), "header load address"),
            (inert_image()[:-32] + bytes(32), "image SHA-256"),
            (inert_image()[:-5], "integrity TLVs"),
            (inert_image(protected=b"bad!"), "protected MCUboot TLVs"),
        ):
            with self.subTest(reason=reason):
                self.replace_fuel_image(data)
                with self.assertRaisesRegex(ValueError, reason):
                    self.check()

    def test_fixture_with_valid_protected_tlvs_and_declared_load_address(self):
        self.replace_fuel_image(inert_image(address=49664, protected=struct.pack("<HH", 0x6908, 4)))
        self.assertEqual(len(self.check()["fuel"]), 64)

    def test_missing_and_duplicate_inner_digests(self):
        data = inert_image()
        for suffix, reason in ((struct.pack("<HH", 0x6907, 4), "image SHA-256"),
                               (struct.pack("<HH", 0x6907, 76) + data[-36:] * 2, "duplicate MCUboot")):
            with self.subTest(reason=reason):
                self.replace_fuel_image(data[:-40] + suffix)
                with self.assertRaisesRegex(ValueError, reason):
                    self.check()

    def test_recognised_image_under_wrong_variant_is_rejected(self):
        with ZipFile(self.root / VARIANTS["water"][0]) as package:
            metadata = json.loads(package.read("manifest.json"))["files"][0]
            with self.assertRaisesRegex(ValueError, "other sensor variant"):
                check_image(package.read("app_update.bin"), metadata, "fuel")

    def test_app_metadata_types(self):
        for key, value in (("releaseNotes", None), ("releaseNotes", 1), ("mandatory", 0),
                           ("versionVerifiable", 0), ("minBatteryVolts", True),
                           ("hardwareRevisions", "all"), ("hardwareRevisions", [" "])):
            with self.subTest(key=key, value=value):
                entry = self.releases[0]
                original = entry.copy()
                entry[key] = value
                with self.assertRaisesRegex(ValueError, key):
                    self.check()
                entry.clear()
                entry.update(original)

    def test_connect_version_ordering(self):
        self.assertEqual(version_key("v2.1+pack"), version_key("2.1.0+new"))
        self.assertLess(version_key("2.1.0-rc1"), version_key("2.1"))
        self.assertLess(version_key("2.1-rc1"), version_key("2.1-rc2"))
        self.assertGreater(version_key("2.10"), version_key("2.9"))

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
