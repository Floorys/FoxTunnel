"""Download a pinned official Windows sing-box build and verify its SHA-256.

Hashes come from the GitHub release assets' digests. No auto-update and no
download at extension startup. This helper is also runnable by itself.
"""
import hashlib
import io
import os
from pathlib import Path
import platform
import urllib.request
import zipfile

VERSION = "1.14.4"
HASHES = {
    "amd64": "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df",
    "arm64": "8cd0a4d0cd8cd480be5731ac31f17038969a42d12add9feb6e031fd43d85bbae",
}


def download():
    machine = os.environ.get("PROCESSOR_ARCHITEW6432") or platform.machine()
    arch = "arm64" if machine.lower() in {"arm64", "aarch64"} else "amd64"
    filename = f"sing-box-{VERSION}-windows-{arch}.zip"
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/{filename}"
    print(f"Downloading official sing-box {VERSION} ({arch})...")
    req = urllib.request.Request(url, headers={"User-Agent": "FoxTunnel-Installer/0.1"})
    with urllib.request.urlopen(req, timeout=90) as response:
        data = response.read(100 * 1024 * 1024 + 1)
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Archive too large")
    if hashlib.sha256(data).hexdigest() != HASHES[arch]:
        raise ValueError("SHA-256 mismatch. Installation aborted.")
    target = Path(__file__).resolve().parent / "bin"
    target.mkdir(exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        # Read only known files; never extract arbitrary paths from an archive.
        prefix = f"sing-box-{VERSION}-windows-{arch}/"
        for name in ("sing-box.exe", "LICENSE"):
            content = archive.read(prefix + name)
            temp = target / (name + ".download")
            temp.write_bytes(content)
            temp.replace(target / name)
    print(f"SHA-256 verified. Installed: {target / 'sing-box.exe'}")


if __name__ == "__main__":
    download()
