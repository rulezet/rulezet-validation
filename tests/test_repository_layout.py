from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST_ROOT = ROOT / "rust"
RUST_FILES = {"Cargo.toml", "Cargo.lock"}


def test_rust_implementation_is_contained_in_rust_directory():
    misplaced = []

    for path in ROOT.rglob("*"):
        if any(part in {".git", ".venv", "target"} for part in path.parts):
            continue
        if path.is_file() and (path.suffix == ".rs" or path.name in RUST_FILES):
            if not path.is_relative_to(RUST_ROOT):
                misplaced.append(path.relative_to(ROOT).as_posix())

    assert misplaced == [], (
        "Rust source and Cargo files must live under rust/: "
        + ", ".join(misplaced)
    )
