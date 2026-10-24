"""Create two synthetic metadata directories claiming the same file."""

import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
args = parser.parse_args()
args.directory.mkdir(parents=True, exist_ok=False)
for name in ("demo_alpha", "demo_beta"):
    directory = args.directory / f"{name}-1.0.dist-info"
    directory.mkdir()
    (directory / "METADATA").write_text(f"Name: {name}\nVersion: 1.0\n", encoding="utf-8")
    (directory / "RECORD").write_text("shared/module.py,,\n", encoding="utf-8")
print("Synthetic conflict created; dist-claims should exit 1.")
