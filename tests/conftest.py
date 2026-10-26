from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
REGISTRY = Path(__file__).parent.parent / "registry"  # deployed by the bundle to ${workspace.file_path}/registry


def fixture_path(name: str) -> Path:
    return FIXTURES / name
