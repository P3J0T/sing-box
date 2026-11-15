#!/usr/bin/env python3
"""Hash working-tree inputs, including staged and new non-ignored files."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def git(*args):
    return subprocess.check_output(["git", *args])


def inventory():
    root = Path.cwd().resolve()
    staged = git("ls-files", "--stage", "-z").split(b"\0")
    files = {}
    for record in filter(None, staged):
        metadata, path = record.split(b"\t", 1)
        mode, oid, stage = metadata.split()
        if stage != b"0":
            raise ValueError("unmerged index entry")
        files[os.fsdecode(path)] = (mode.decode(), oid.decode())
    for path in filter(None, git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")):
        files[os.fsdecode(path)] = ("untracked", "")
    entries = []
    for name, (index_mode, oid) in sorted(files.items()):
        if name.startswith("/") or ".." in Path(name).parts:
            raise ValueError("unsafe source path: " + name)
        path = root / name
        if not path.parent.resolve().is_relative_to(root):
            raise ValueError("source path aliases outside repository: " + name)
        if index_mode == "160000":
            # Gitlinks are pinned by the index, but their checked-out contents
            # are not part of the root module and must not be silently used.
            entries.append({"path": name, "kind": "gitlink", "index_oid": oid})
            continue
        mode = path.lstat().st_mode
        entry = {"path": name, "mode": stat.S_IMODE(mode)}
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            if not path.resolve().is_relative_to(root):
                raise ValueError("source symlink aliases outside repository: " + name)
            if not path.resolve().is_file():
                raise ValueError("source symlink is not a file: " + name)
            entry.update(kind="symlink", target=target)
            path = path.resolve()
        elif stat.S_ISREG(mode):
            entry["kind"] = "file"
        else:
            raise ValueError("unsupported source input type: " + name)
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        entry["sha256"] = digest.hexdigest()
        entries.append(entry)
    serialized = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {"algorithm": "sha256-canonical-json-v1", "digest": hashlib.sha256(serialized.encode()).hexdigest(), "entries": entries}


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("capture", "verify"):
        raise ValueError("usage: source_manifest.py capture|verify MANIFEST")
    path = Path(sys.argv[2])
    current = inventory()
    if sys.argv[1] == "capture":
        with path.open("x") as stream:
            json.dump(current, stream, sort_keys=True, indent=2)
            stream.write("\n")
    else:
        expected = json.loads(path.read_text())
        if current != expected:
            before = {item["path"]: item for item in expected["entries"]}
            after = {item["path"]: item for item in current["entries"]}
            changed = [name for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)]
            raise ValueError("source/input drift; changed paths: " + ", ".join(changed))
    print(current["digest"])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
