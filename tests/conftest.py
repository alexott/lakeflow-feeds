from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_path(name: str) -> Path:
    return FIXTURES / name
