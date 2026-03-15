"""Тесты TrapRegistry (core/traps.py)."""

import json
from pathlib import Path

import pytest

from phantom.core.traps import TrapEntry, TrapRegistry


def _entry(trap_id="t1", output="a/b.txt", category="credential",
           priority="critical", template="text/t.j2", fmt="text") -> TrapEntry:
    return TrapEntry(
        trap_id=trap_id, output_path=output, category=category,
        priority=priority, template=template, fmt=fmt,
    )


# ---------- register / lookup ----------

def test_registry_lookup(tmp_path: Path) -> None:
    traps_root = tmp_path / "traps"
    traps_root.mkdir()
    reg = TrapRegistry(str(traps_root))
    reg.register(_entry())
    found = reg.lookup(str(traps_root / "a" / "b.txt"))
    assert found is not None
    assert found.trap_id == "t1"


def test_lookup_missing_returns_none(tmp_path: Path) -> None:
    reg = TrapRegistry(str(tmp_path))
    assert reg.lookup(str(tmp_path / "nonexistent.txt")) is None


def test_contains(tmp_path: Path) -> None:
    reg = TrapRegistry(str(tmp_path))
    reg.register(_entry(output="secret.txt"))
    assert reg.contains(str(tmp_path / "secret.txt")) is True
    assert reg.contains(str(tmp_path / "other.txt")) is False


def test_entries_list(tmp_path: Path) -> None:
    reg = TrapRegistry(str(tmp_path))
    reg.register(_entry(trap_id="a", output="one.txt"))
    reg.register(_entry(trap_id="b", output="two.txt"))
    assert len(reg.entries()) == 2
    ids = {e.trap_id for e in reg.entries()}
    assert ids == {"a", "b"}


def test_register_overwrites(tmp_path: Path) -> None:
    """Повторная регистрация по тому же пути перезаписывает запись."""
    reg = TrapRegistry(str(tmp_path))
    reg.register(_entry(trap_id="v1", output="file.txt"))
    reg.register(_entry(trap_id="v2", output="file.txt"))
    found = reg.lookup(str(tmp_path / "file.txt"))
    assert found.trap_id == "v2"
    assert len(reg.entries()) == 1


# ---------- normalize ----------

def test_normalize_relative_path(tmp_path: Path) -> None:
    reg = TrapRegistry(str(tmp_path))
    result = reg.normalize("sub/file.txt")
    assert result == str(tmp_path / "sub" / "file.txt")


def test_normalize_absolute_path(tmp_path: Path) -> None:
    reg = TrapRegistry(str(tmp_path))
    full = str(tmp_path / "dir" / "file.txt")
    assert reg.normalize(full) == full


def test_normalize_path_traversal_blocked(tmp_path: Path) -> None:
    """Путь, выходящий за корень, вызывает ValueError."""
    reg = TrapRegistry(str(tmp_path / "traps"))
    with pytest.raises(ValueError, match="Path escapes traps root"):
        reg.normalize("/etc/passwd")


def test_lookup_path_traversal_returns_none(tmp_path: Path) -> None:
    """lookup() для path traversal возвращает None (а не бросает)."""
    reg = TrapRegistry(str(tmp_path / "traps"))
    assert reg.lookup("/etc/passwd") is None


# ---------- export / import JSON ----------

def test_export_import_roundtrip(tmp_path: Path) -> None:
    traps_root = tmp_path / "traps"
    traps_root.mkdir()
    reg = TrapRegistry(str(traps_root))
    reg.register(_entry(trap_id="t1", output="a.txt"))
    reg.register(_entry(trap_id="t2", output="b.txt", category="infra"))

    export_path = str(tmp_path / "registry.json")
    reg.export_json(export_path)
    assert Path(export_path).exists()

    loaded = TrapRegistry.from_json(export_path)
    assert len(loaded.entries()) == 2
    assert loaded.lookup(str(traps_root / "a.txt")).trap_id == "t1"
    assert loaded.lookup(str(traps_root / "b.txt")).category == "infra"


def test_export_json_content(tmp_path: Path) -> None:
    reg = TrapRegistry(str(tmp_path))
    reg.register(_entry(trap_id="x1", output="test.txt"))
    path = str(tmp_path / "out.json")
    reg.export_json(path)
    data = json.loads(Path(path).read_text())
    assert data["root"] == str(tmp_path)
    assert len(data["traps"]) == 1
    assert data["traps"][0]["trap_id"] == "x1"


def test_reload_from_json(tmp_path: Path) -> None:
    root1 = tmp_path / "root1"
    root1.mkdir()
    reg = TrapRegistry(str(root1))
    reg.register(_entry(trap_id="old", output="old.txt"))

    root2 = tmp_path / "root2"
    root2.mkdir()
    reg2 = TrapRegistry(str(root2))
    reg2.register(_entry(trap_id="new", output="new.txt"))
    export_path = str(tmp_path / "reg2.json")
    reg2.export_json(export_path)

    with pytest.raises(ValueError):
        reg.reload_from_json(export_path)
    assert reg.root == str(root1)
    assert len(reg.entries()) == 1
    assert reg.entries()[0].trap_id == "old"


# ---------- from_entries ----------

def test_from_entries(tmp_path: Path) -> None:
    entries = [
        _entry(trap_id="a", output="x.txt"),
        _entry(trap_id="b", output="y.txt"),
    ]
    reg = TrapRegistry.from_entries(str(tmp_path), entries)
    assert len(reg.entries()) == 2


# ---------- TrapEntry ----------

def test_entry_to_dict() -> None:
    e = _entry()
    d = e.to_dict()
    assert d["trap_id"] == "t1"
    assert d["format"] == "text"
    assert "output_path" in d


def test_entry_frozen() -> None:
    e = _entry()
    with pytest.raises(AttributeError):
        e.trap_id = "changed"


# ---------- root property ----------

def test_root_property(tmp_path: Path) -> None:
    reg = TrapRegistry(str(tmp_path))
    assert reg.root == str(tmp_path.resolve())
