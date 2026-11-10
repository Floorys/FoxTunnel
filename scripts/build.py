"""Build an unsigned Firefox XPI; an AMO signature is required for release Firefox."""
from pathlib import Path
import json
import zipfile

ROOT = Path(__file__).resolve().parent.parent
manifest = json.loads((ROOT / "extension" / "manifest.json").read_text(encoding="utf-8"))
target = ROOT / "dist" / f"foxtunnel-{manifest['version']}.xpi"
target.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for file in sorted((ROOT / "extension").rglob("*")):
        if file.is_file():
            archive.write(file, file.relative_to(ROOT / "extension").as_posix())
print(f"Built unsigned extension: {target}")
