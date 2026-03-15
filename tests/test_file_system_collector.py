"""Тесты FileSystemCollector."""

import phantom.telemetry.file_system as fs
from phantom.core.traps import TrapEntry, TrapRegistry


def test_file_system_collector_trap_match(tmp_path, monkeypatch):
    traps_root = tmp_path / "traps"
    traps_root.mkdir()
    trap_file = traps_root / "secret.txt"
    trap_file.write_text("x", encoding="utf-8")

    reg = TrapRegistry.from_entries(
        str(traps_root),
        [
            TrapEntry(
                trap_id="trap-1",
                output_path=str(trap_file),
                category="credentials",
                priority="high",
                template="tpl",
                fmt="text",
            )
        ],
    )
    reg_path = tmp_path / "registry.json"
    reg.export_json(str(reg_path))

    monkeypatch.setattr(fs, "get_config", lambda: {"paths": {"trap_registry_file": str(reg_path)}})
    collector = fs.FileSystemCollector()
    info = collector._collect_sync(str(trap_file))
    assert info is not None
    assert info.trap_id == "trap-1"
    assert info.trap_type == "credentials"


def test_file_system_collector_missing_file(monkeypatch):
    monkeypatch.setattr(fs, "get_config", lambda: {"paths": {"trap_registry_file": "/nonexistent.json"}})
    collector = fs.FileSystemCollector()
    assert collector._collect_sync("/nonexistent/path") is None
