"""Check the Safiery Connect test manifest against its two local Nordic packages."""

import hashlib
import json
from pathlib import Path
import re
import sys
from zipfile import BadZipFile, ZipFile


ROOT = Path(__file__).resolve().parents[1]
RAW_URL = "https://raw.githubusercontent.com/Safiery/startank-ota-bins/main/"
SLOT_BYTES = 466_944
VARIANTS = {
    "fuel": ("startank/fuel/StarTankFuelOTA.zip", "StarTankFuel1"),
    "water": ("startank/water/StarTankWaterOTA.zip", "StarTank"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_package(root, release):
    variant = release["variant"]
    path, image_name = VARIANTS[variant]
    for field in ("version", "minAppVersion"):
        value = release.get(field)
        if field == "minAppVersion" and value is None:
            continue
        core = value.strip().removeprefix("v").split("+")[0].split("-")[0] if isinstance(value, str) else ""
        require(re.fullmatch(r"[0-9]+(?:[.][0-9]+){0,2}", core)
                and all(int(part) <= 2147483647 for part in core.split(".")),
                f"{variant}: invalid {field} for Safiery Connect")
    package = root / path
    require(package.resolve() == package, f"{variant}: package path must be local")
    require(release["url"] == RAW_URL + path, f"{variant}: unexpected download URL")
    size = package.stat().st_size
    require(0 < size <= 2 * SLOT_BYTES and size == release["sizeBytes"],
            f"{variant}: ZIP size mismatch or outside package limit")
    require(hashlib.sha256(package.read_bytes()).hexdigest() == release["sha256"],
            f"{variant}: ZIP checksum mismatch")

    with ZipFile(package) as archive:
        require(sorted(archive.namelist()) == ["app_update.bin", "manifest.json"],
                f"{variant}: expected one image and one Nordic manifest")
        require(archive.getinfo("manifest.json").file_size <= 65536,
                f"{variant}: Nordic manifest too large")
        image_size = archive.getinfo("app_update.bin").file_size
        require(0 < image_size <= SLOT_BYTES and image_size == release["imageSizeBytes"],
                f"{variant}: image size mismatch or outside device slot")
        nordic = json.loads(archive.read("manifest.json"))
        require(nordic["name"] == image_name == release["mcubootName"],
                f"{variant}: package belongs to a different sensor variant")
        require(nordic["format-version"] == 0 and len(nordic["files"]) == 1,
                f"{variant}: unexpected Nordic package format")
        image = nordic["files"][0]
        require(image["file"] == "app_update.bin" and image["type"] == "application"
                and image["size"] == image_size, f"{variant}: Nordic image mismatch")
        for inner, outer in (("board", "board"), ("soc", "soc"),
                             ("version_MCUBOOT", "mcubootVersion"),
                             ("load_address", "loadAddress")):
            require(image[inner] == release[outer], f"{variant}: {outer} mismatch")
        require(image["board"] == "Star Tank" and image["soc"] == "nRF52840_QIAA"
                and image["load_address"] == 49664, f"{variant}: wrong hardware or load address")
        require(release["imageMode"] == "confirmOnly", f"{variant}: wrong legacy image mode")
        require(archive.testzip() is None, f"{variant}: ZIP member integrity check failed")


def check_manifest(root):
    manifest = json.loads((root / "manifest.json").read_text())
    require(manifest["schemaVersion"] == 1 and manifest["channel"] == "test",
            "expected the version 1 test-channel manifest")
    products = manifest["products"]
    require(len(products) == 1 and products[0]["product"] == "star-tank",
            "expected one StarTank product")
    releases = products[0]["releases"]
    require(sorted(entry["variant"] for entry in releases) == sorted(VARIANTS),
            "expected one fuel and one water release")
    for release in releases:
        check_package(root, release)


if __name__ == "__main__":
    try:
        check_manifest(ROOT)
    except (OSError, ValueError, KeyError, TypeError, IndexError, BadZipFile) as error:
        sys.exit(f"OTA package check failed: {error}")
    print("StarTank fuel and water packages match the test manifest.")
