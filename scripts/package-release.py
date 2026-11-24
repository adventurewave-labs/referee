#!/usr/bin/env python3
"""Build reproducible Referee release assets from a clean Git checkout."""

import argparse
import gzip
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
GRAPHICS = (
    "referee-mark.svg",
    "referee-banner.svg",
    "referee-infographic.svg",
    "referee-infographic.png",
)


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def binary_archive(folder, platform, prefix, timestamp, scratch):
    system, architecture = platform.split("/")
    binary = scratch / "referee"
    env = {**os.environ, "GOOS": system, "GOARCH": architecture, "CGO_ENABLED": "0"}
    subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(binary), "./cmd/referee"],
                   cwd=ROOT, env=env, check=True)
    if system == "linux" and sys.platform == "linux" and os.uname().machine == "x86_64":
        subprocess.run([str(binary), "policy", "check", "--policy", "examples/policy-coding-agent.yaml"],
                       cwd=ROOT, check=True)
    archive = folder / f"{prefix}-{system}-{architecture}.tar.gz"
    with archive.open("wb") as output, gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as package:
            for source, name, mode in (
                (binary, "referee", 0o755),
                (ROOT / "LICENSE", "LICENSE", 0o644),
                (ROOT / "README.md", "README.md", 0o644),
                (ROOT / "examples/policy-coding-agent.yaml", "examples/policy-coding-agent.yaml", 0o644),
            ):
                entry = tarfile.TarInfo(f"{prefix}/{name}")
                entry.size = source.stat().st_size
                entry.mode = mode
                entry.mtime = timestamp
                with source.open("rb") as data:
                    package.addfile(entry, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Release tag such as v0.1.0")
    parser.add_argument("--out", required=True, type=Path, help="New directory outside the checkout")
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag):
        parser.error("expected a version tag such as v0.1.0")
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents or out.exists():
        parser.error("--out must be a new directory outside the checkout")
    if git("status", "--porcelain"):
        parser.error("package the exact release commit from a clean checkout")

    head = git("rev-parse", "HEAD").decode().strip()
    timestamp = int(git("show", "-s", "--format=%ct", head))
    prefix = f"referee-{args.tag}"
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out.parent, prefix=".referee-package-") as temporary:
        scratch = Path(temporary)
        folder = scratch / "assets"
        folder.mkdir()
        for platform in ("linux/amd64", "darwin/arm64"):
            binary_archive(folder, platform, prefix, timestamp, scratch)
        (folder / f"{prefix}-landing.zip").write_bytes(git("archive", "--format=zip", head, "LICENSE", "docs"))
        source = git("archive", "--format=tar", f"--prefix={prefix}/", head)
        (folder / f"{prefix}-source.tar.gz").write_bytes(gzip.compress(source, mtime=0))
        shutil.copyfile(ROOT / "LICENSE", folder / "LICENSE")
        for name in GRAPHICS:
            shutil.copyfile(ROOT / "docs/assets" / name, folder / name)
        manifest = [f"{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n"
                    for asset in sorted(folder.iterdir())]
        (folder / "SHA256SUMS").write_text("".join(manifest), encoding="utf-8")
        out.mkdir()
        try:
            folder.replace(out)
        except OSError:
            out.rmdir()
            raise
    print(f"Packaged {args.tag} from {head} in {out}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError) as error:
        sys.exit(f"Package stopped: {error}")
