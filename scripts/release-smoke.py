#!/usr/bin/env python3
"""Install and exercise the verified Linux release archive in a clean workspace."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("tag")
    args = parser.parse_args()

    records = (line.split("  ", 1) for line in Path("SHA256SUMS").read_text().splitlines())
    expected = {name: checksum for checksum, name in records}.get(args.archive.name)
    actual = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit("Release archive does not match SHA256SUMS")

    with tarfile.open(args.archive, "r:gz") as archive, \
            tempfile.TemporaryDirectory(prefix="referee-install-") as directory:
        root = Path(directory)
        for name, target in (
            ("referee", root / "referee"),
            ("examples/policy-coding-agent.yaml", root / "policy.yaml"),
        ):
            member = archive.getmember(f"referee-{args.tag}/{name}")
            if not member.isfile():
                raise SystemExit(f"Expected a regular release file: {name}")
            with archive.extractfile(member) as source:
                target.write_bytes(source.read())

        binary = root / "referee"
        binary.chmod(0o700)
        subprocess.run([str(binary), "policy", "check", "--policy", "policy.yaml"],
                       cwd=root, check=True, timeout=15)
        demo = subprocess.run([str(binary), "demo"], cwd=root, check=True, timeout=20,
                              capture_output=True, text=True)
        lines = demo.stdout.splitlines()
        if not any(line.startswith("[CLEAN CALL]") and "forwarded=true" in line for line in lines):
            raise SystemExit("The installed demo did not forward its clean tool call")
        if not any(line.startswith("[task-end]") and "forwarded=false" in line for line in lines):
            raise SystemExit("The installed demo did not revoke the completed task capability")
        if not any(line.startswith("[verify] receipt chain ok:") for line in lines):
            raise SystemExit("The installed demo did not verify its receipt chain")
        print("PASS installed Referee policy, clean call, task-end revocation, and receipt verification.")


if __name__ == "__main__":
    main()
