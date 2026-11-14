"""
Collect dependency notices from the locked Cargo sources for binary distribution.
"""

import json
import subprocess
from pathlib import Path


def main() -> None:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--filter-platform",
            "x86_64-unknown-linux-musl",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    metadata = json.loads(result.stdout)
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    included = set()
    pending = [metadata["resolve"]["root"]]
    while pending:
        identifier = pending.pop()
        if identifier in included:
            continue
        included.add(identifier)
        pending.extend(dependency["pkg"] for dependency in nodes[identifier]["deps"])
    sections = [
        "# 第三方依赖声明\n",
        "以下保留 Cargo.lock 对应依赖随源码提供的许可和声明。\n",
    ]
    for package in sorted(
        metadata["packages"], key=lambda item: (item["name"], item["version"])
    ):
        if package["source"] is None or package["id"] not in included:
            continue
        directory = Path(package["manifest_path"]).parent
        files = []
        for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*", "UNLICENSE*"):
            files.extend(path for path in directory.glob(pattern) if path.is_file())
        for folder in ("LICENSES", "licenses"):
            if (directory / folder).is_dir():
                files.extend(
                    path for path in (directory / folder).rglob("*") if path.is_file()
                )
        if package.get("license_file"):
            files.append(directory / package["license_file"])
        sections.append(f"## {package['name']} {package['version']}\n")
        sections.append(f"License: {package.get('license') or 'see included notice'}\n")
        if not files:
            raise RuntimeError(f"Missing dependency notice: {package['name']}")
        for path in sorted(set(files)):
            sections.append(
                f"### {path.name}\n\n```text\n{path.read_text(encoding='utf-8')}\n```\n"
            )
    Path("THIRD_PARTY_NOTICES.md").write_text("\n".join(sections), encoding="utf-8")


if __name__ == "__main__":
    main()
