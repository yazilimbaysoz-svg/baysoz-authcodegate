# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Release-hygiene, attribution and no-stub gates by Baysöz Labs <baysozlabs@proton.me>."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = "Baysöz Labs <baysozlabs@proton.me>"
PUBLIC_FILES = (
    "README.md",
    "LICENSE",
    "pyproject.toml",
    "SECURITY.md",
    "CHANGELOG.md",
    "PLAN.md",
    "docs/MARKET_RESEARCH.md",
    "docs/ARCHITECTURE.md",
    "docs/TRIBUNAL.md",
    ".github/workflows/ci.yml",
    ".gitignore",
)
STUB_MARKERS = (r"\bTODO\b", r"\bFIXME\b", "NotImplementedError", r"^\s*pass\s*$", r"^\s*\.\.\.\s*$")


def test_every_public_file_attributes_baysöz_labs():
    missing = []
    for relative in PUBLIC_FILES:
        path = ROOT / relative
        if not path.exists() or VENDOR not in path.read_text(encoding="utf-8"):
            missing.append(relative)
    assert missing == []


def test_source_files_have_attribution_and_no_stubs():
    offenders = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        content = path.read_text(encoding="utf-8")
        if VENDOR not in content:
            offenders.append(f"{path.name}: attribution")
        for marker in STUB_MARKERS:
            if re.search(marker, content, re.MULTILINE):
                offenders.append(f"{path.name}: {marker}")
    assert offenders == []
