"""
Version bump helper script for guard-core-rs.

Updates the version string across every workspace member crate and the
files that must stay in sync with it:
- crates/*/Cargo.toml ([package].version for each member crate)
- Cargo.toml ([workspace.dependencies] path+version pins for
  guard-core-engine and guard-core-rs)
- Cargo.lock ([[package]] version entries for the workspace crates)
- CHANGELOG.md (inserts a version scaffold at the top for manual editing)

Usage:
    python .github/scripts/bump_version.py <version>
    make bump-version VERSION=x.y.z

No external dependencies required - stdlib only.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Resolve project root relative to this script's location
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

CRATES_DIR = PROJECT_ROOT / "crates"

VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")

# Internal crates that must never be published to crates.io
PUBLISH_FALSE = {
    "guard-core-benchmark",
    "guard-core-conformance",
    "guard-core-python",
}

WORKSPACE_PIN_PATTERN = re.compile(
    r'^(?P<name>guard-core-[a-z]+)\s*=\s*\{\s*path\s*=\s*"(?P<path>[^"]+)",\s*'
    r'version\s*=\s*"(?P<version>[^"]+)"\s*\}',
    re.MULTILINE,
)


def update_crate_manifest(manifest: Path, version: str) -> bool:
    """Update [package].version in a member crate's Cargo.toml."""
    content = manifest.read_text()
    pattern = re.compile(r'^(version\s*=\s*)"[^"]*"', re.MULTILINE)
    match = pattern.search(content)
    if not match:
        print(f"  ERROR: no version field in {manifest.relative_to(PROJECT_ROOT)}")
        return False
    current = re.search(r'"([^"]*)"', match.group(0))
    if current and current.group(1) == version:
        print(f"  {manifest.relative_to(PROJECT_ROOT)}: already set to {version}")
        return True
    new_content = pattern.sub(lambda m: f'{m.group(1)}"{version}"', content, count=1)
    manifest.write_text(new_content)
    print(f"  {manifest.relative_to(PROJECT_ROOT)}: updated to {version}")
    return True


def update_workspace_pins(version: str) -> bool:
    """Update [workspace.dependencies] path+version pins in the root Cargo.toml."""
    path = PROJECT_ROOT / "Cargo.toml"
    content = path.read_text()

    changed = False

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        if match.group("version") != version:
            changed = True
        return f'{match.group("name")} = {{ path = "{match.group("path")}", version = "{version}" }}'

    new_content = WORKSPACE_PIN_PATTERN.sub(repl, content)
    if not changed:
        print("  Cargo.toml [workspace.dependencies]: already up to date")
        return True
    path.write_text(new_content)
    print(f"  Cargo.toml [workspace.dependencies]: updated pins to {version}")
    return True


def update_cargo_lock(version: str) -> bool:
    """Update the [[package]] version entries of workspace crates in Cargo.lock."""
    path = PROJECT_ROOT / "Cargo.lock"
    if not path.exists():
        print("  ERROR: Cargo.lock not found")
        return False
    content = path.read_text()

    ok = True
    for manifest in sorted(CRATES_DIR.glob("*/Cargo.toml")):
        crate = manifest.parent.name
        pattern = re.compile(
            r'(\[\[package\]\]\nname = "%s"\nversion = )"[^"]*"' % re.escape(crate)
        )
        new_content, n = pattern.subn(r'\1"%s"' % version, content)
        if n == 0:
            print(f"  WARNING: no Cargo.lock entry found for crate {crate}")
            continue
        if new_content != content:
            print(f"  Cargo.lock: {crate} updated to {version}")
        content = new_content
    path.write_text(content)
    return ok


def insert_changelog_scaffold(version: str) -> bool:
    """Insert a version scaffold block at the top of CHANGELOG.md.

    Mirrors guard-agent's bump_version.py scaffold behavior, adapted to
    this repo's keep-a-changelog style.
    """
    path = PROJECT_ROOT / "CHANGELOG.md"
    if not path.exists():
        print("  ERROR: CHANGELOG.md not found")
        return False
    content = path.read_text()
    today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

    if f"## [{version}]" in content:
        print(f"  CHANGELOG.md: {version} entry already exists")
        return True

    scaffold = (
        f"## [{version}] - {today}\n"
        f"\n"
        f"### Added\n"
        f"\n"
        f"- (v{version}) describe additions here\n"
        f"\n"
        f"### Changed\n"
        f"\n"
        f"- (v{version}) describe changes here\n"
        f"\n"
    )

    # Insert before the first existing version heading ([Unreleased] included)
    heading_pattern = re.compile(r"^## \[", re.MULTILINE)
    match = heading_pattern.search(content)
    if match:
        insert_pos = match.start()
        new_content = content[:insert_pos] + scaffold + content[insert_pos:]
    else:
        new_content = content.rstrip() + "\n\n" + scaffold

    path.write_text(new_content)
    print(f"  CHANGELOG.md: added v{version} scaffold")
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: bump_version.py <version>")
        print("  version must be in X.Y.Z format")
        return 1

    version = sys.argv[1]

    if not VERSION_PATTERN.match(version):
        print(f"Error: '{version}' is not a valid version. Expected format: X.Y.Z")
        return 1

    print(f"Bumping version to {version}...\n")

    ok = True

    manifests = sorted(CRATES_DIR.glob("*/Cargo.toml"))
    if not manifests:
        print("  ERROR: no crates/*/Cargo.toml manifests found")
        ok = False

    for manifest in manifests:
        crate = manifest.parent.name
        if crate in PUBLISH_FALSE:
            print(f"  {crate}: internal crate (publish = false), bumping version only")
        try:
            if not update_crate_manifest(manifest, version):
                ok = False
        except Exception as e:
            print(f"\n  ERROR updating {manifest}: {e}")
            ok = False

    for name, updater in [
        ("Cargo.toml workspace pins", update_workspace_pins),
        ("Cargo.lock", update_cargo_lock),
        ("CHANGELOG.md scaffold", insert_changelog_scaffold),
    ]:
        try:
            if not updater(version):
                print(f"\n  FAILED: {name}")
                ok = False
        except Exception as e:
            print(f"\n  ERROR updating {name}: {e}")
            ok = False

    print()
    if ok:
        print("Version bump complete.")
        print("Next steps: edit the CHANGELOG.md scaffold, then commit and tag.")
    else:
        print("Version bump completed with errors.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
