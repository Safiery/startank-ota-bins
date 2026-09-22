# STAR-Tank OTA firmware — distribution

Serves the firmware manifest and images that the **Safiery Connect** app fetches over the air.

This repository is deliberately **public and contains nothing but distribution artefacts**. The app
reads `manifest.json` with no credentials, which a private repository cannot support: GitHub does
not serve `raw.githubusercontent.com` for private repos without a token, and a token shipped inside
an APK is extractable by anyone who downloads it.

## Layout

```
manifest.json                            what the app fetches first
startank/fuel/StarTankFuelOTA.zip        fuel variant
startank/water/StarTankWaterOTA.zip      water variant
```

## Identifying a build

No STAR-Tank build reports a usable version — every one reports MCUboot `0.0.0+0` — so firmware is
identified by the **SHA-256 of the image inside the zip**, not by a version string:

| Variant | MCUboot image hash |
|---|---|
| fuel  | `eb2cd2d116501d6e289e99ff957f0a243b416332a2d03001bfd509a015298c5e` |
| water | `998109a16869ec0fc549868f5f9be467f23189480f7cb242e2e5b4f3428b9d33` |

The app verifies each download against the `sha256` in the manifest (of the zip) before it will
flash anything.

## ⚠️ These are test builds

They are **not for production or customer use**:

- Built from STAR-Tank firmware `ea91b64`; the fuel image came from a **dirty working tree** and is
  not reproducible from git.
- Signed with MCUboot's **public sample key**, so the signature proves nothing about origin.

Production hosting is still to be decided — who owns the domain, who publishes the manifest, and
what the release-approval process is. When that exists, this repository should be retired rather
than promoted.
