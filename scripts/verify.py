"""Run all local FoxTunnel verification checks in one command."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "native" / "bin" / ("sing-box.exe" if sys.platform == "win32" else "sing-box")


def run_step(label: str, cmd: list[str]) -> None:
    print(f"\n==> {label}")
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def verify_json_files() -> None:
    print("\n==> Checking manifest and test config JSON files")
    manifest = json.loads((ROOT / "extension" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["manifest_version"] == 2
    for cfg in sorted((ROOT / "tests" / "configs").glob("*.json")):
        json.loads(cfg.read_text(encoding="utf-8"))
        print(f"OK JSON: {cfg.relative_to(ROOT)}")


def verify_xpi() -> None:
    print("\n==> Verifying built XPI structure")
    manifest = json.loads((ROOT / "extension" / "manifest.json").read_text(encoding="utf-8"))
    xpi = ROOT / "dist" / f"foxtunnel-{manifest['version']}.xpi"
    if not xpi.is_file():
        raise SystemExit(f"Missing XPI: {xpi}")
    expected = {
        "manifest.json",
        "background.js",
        "lib.js",
        "popup.html",
        "popup.js",
        "options.html",
        "options.js",
        "style.css",
        "theme.js",
        "icons/tunnel.svg",
    }
    with zipfile.ZipFile(xpi, "r") as zf:
        names = set(zf.namelist())
        missing = expected - names
        if missing:
            raise SystemExit(f"XPI missing files: {sorted(missing)}")
        bad = zf.testzip()
        if bad is not None:
            raise SystemExit(f"Corrupt zip entry in XPI: {bad}")
    print(f"OK XPI: {xpi} ({len(names)} files)")


def main() -> None:
    run_step("Python compileall", [sys.executable, "-m", "compileall", "native", "scripts", "tests"])
    verify_json_files()
    run_step("Python unit tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])

    if CORE.is_file():
        for cfg in sorted((ROOT / "tests" / "configs").glob("*.json")):
            run_step(f"sing-box check ({cfg.name})", [str(CORE), "check", "-c", str(cfg)])
    else:
        print(f"\nWARN: {CORE} not found, skipping sing-box check.")

    run_step("Build XPI", [sys.executable, "scripts/build.py"])
    verify_xpi()

    node = shutil.which("node")
    if node:
        run_step("JavaScript tests (lib.js)", [node, "tests/test_lib.js"])
    else:
        print("\nSKIP: Node.js not found in PATH; skipping tests/test_lib.js.")

    print("\nALL CHECKS PASSED.")


if __name__ == "__main__":
    main()

