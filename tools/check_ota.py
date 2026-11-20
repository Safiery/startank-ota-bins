"""Check the Safiery Connect test manifest against its two local Nordic packages."""

import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from zipfile import BadZipFile, ZipFile


ROOT = Path(__file__).resolve().parents[1]
RAW_URL = "https://raw.githubusercontent.com/Safiery/startank-ota-bins/main/"
SLOT_BYTES = 466_944
VARIANTS = {
    "fuel": ("startank/fuel/StarTankFuelOTA.zip", "StarTankFuel1"),
    "water": ("startank/water/StarTankWaterOTA.zip", "StarTank"),
}
KNOWN_IMAGES = {
    "eb2cd2d116501d6e289e99ff957f0a243b416332a2d03001bfd509a015298c5e": "fuel",
    "998109a16869ec0fc549868f5f9be467f23189480f7cb242e2e5b4f3428b9d33": "water",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version_key(value):
    """Safiery Connect ignores build metadata and compares prereleases lexically."""
    require(isinstance(value, str), "invalid version for Safiery Connect")
    text = value.strip().removeprefix("v").split("+", 1)[0]
    core, _, prerelease = text.partition("-")
    require(re.fullmatch(r"[0-9]+(?:[.][0-9]+){0,2}", core), "invalid version for Safiery Connect")
    numbers = [int(part) for part in core.split(".")]
    require(max(numbers) <= 2147483647, "invalid version for Safiery Connect")
    numbers.extend([0] * (3 - len(numbers)))
    return (*numbers, not prerelease, prerelease.encode("utf-16-be", errors="surrogatepass"))


def check_metadata(release):
    variant = release["variant"]
    for field in ("version", "minAppVersion"):
        value = release.get(field)
        if field == "minAppVersion" and value is None:
            continue
        version_key(value)
    require("releaseNotes" not in release or isinstance(release["releaseNotes"], str),
            f"{variant}: releaseNotes must be text")
    for field in ("versionVerifiable", "mandatory"):
        require(field not in release or type(release[field]) is bool, f"{variant}: {field} must be boolean")
    for field in ("sizeBytes", "imageSizeBytes", "loadAddress"):
        value = release[field]
        require(type(value) in (int, float) and 0 < value < 2**53 and value == int(value),
                f"{variant}: {field} must be a positive integer")
    if "minBatteryVolts" in release:
        voltage = release["minBatteryVolts"]
        require(type(voltage) in (int, float) and 0 < voltage <= sys.float_info.max,
                f"{variant}: minBatteryVolts must be a positive finite number")
    if "hardwareRevisions" in release:
        revisions = release["hardwareRevisions"]
        require(isinstance(revisions, list) and all(isinstance(r, str) and r.strip() for r in revisions),
                f"{variant}: hardwareRevisions must contain nonempty strings")


def check_image(data, metadata, variant):
    """Validate MCUboot structure and its embedded image digest as Connect does."""
    require(36 <= len(data) <= SLOT_BYTES, "invalid MCUboot image size")
    magic, address, header_size, protected_size, body_size, flags = struct.unpack_from("<IIHHII", data)
    require(magic == 0x96F3B83D and header_size >= 32 and header_size % 4 == 0
            and body_size > 0 and not flags & 0x3C, "invalid MCUboot image header")
    major, minor, revision, build = struct.unpack_from("<BBHI", data, 20)
    require(f"{major}.{minor}.{revision}+{build}" == metadata["version_MCUBOOT"],
            "MCUboot header version differs from package")
    require(address in (0, metadata["load_address"]), "MCUboot header load address differs from package")

    body_end = header_size + body_size
    hash_end = body_end + protected_size
    require(hash_end + 4 <= len(data), "truncated MCUboot image or protected TLVs")
    if protected_size:
        require(protected_size >= 4 and struct.unpack_from("<HH", data, body_end) == (0x6908, protected_size),
                "invalid protected MCUboot TLVs")
    marker, length = struct.unpack_from("<HH", data, hash_end)
    end = hash_end + length
    require(marker == 0x6907 and length >= 4 and end <= len(data), "invalid MCUboot integrity TLVs")
    cursor = hash_end + 4
    embedded = None
    while cursor < end:
        require(cursor + 4 <= end, "truncated MCUboot TLV header")
        kind, size = struct.unpack_from("<HH", data, cursor)
        cursor += 4
        require(cursor + size <= end, "truncated MCUboot TLV value")
        if kind == 0x10:
            require(size == 32 and embedded is None, "invalid or duplicate MCUboot SHA-256")
            embedded = data[cursor:cursor + size]
        cursor += size
    digest = hashlib.sha256(data[:hash_end]).digest()
    require(embedded == digest, "MCUboot image SHA-256 mismatch")
    require(KNOWN_IMAGES.get(digest.hex(), variant) == variant, "MCUboot image belongs to the other sensor variant")
    return digest.hex()


def check_package(root, release):
    variant = release["variant"]
    path, image_name = VARIANTS[variant]
    check_metadata(release)
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
        return check_image(archive.read("app_update.bin"), image, variant)


def check_manifest(root):
    manifest = json.loads((root / "manifest.json").read_text())
    require(type(manifest["schemaVersion"]) in (int, float) and manifest["schemaVersion"] == 1
            and manifest["channel"] == "test",
            "expected the version 1 test-channel manifest")
    for field in ("generatedAt", "notice"):
        require(manifest.get(field) is None or isinstance(manifest[field], str), f"{field} must be text or null")
    products = manifest["products"]
    require(len(products) == 1 and products[0]["product"] == "star-tank",
            "expected one StarTank product")
    releases = products[0]["releases"]
    require(sorted(entry["variant"] for entry in releases) == sorted(VARIANTS),
            "expected one fuel and one water release")
    return {release["variant"]: check_package(root, release) for release in releases}


if __name__ == "__main__":
    try:
        check_manifest(ROOT)
    except (OSError, ValueError, KeyError, TypeError, IndexError, BadZipFile) as error:
        sys.exit(f"OTA package check failed: {error}")
    print("StarTank fuel and water packages match the test manifest.")
