"""Тесты цепочки целостности улик."""

import json

import phantom.response.forensics as forensics


class _DummyPrecapture:
    def export_window(self, *args, **kwargs):  # noqa: ANN001,D401
        return False


def test_chain_state_updates(tmp_path, monkeypatch):
    chain_state = tmp_path / "chain_state.json"
    cfg = {
        "forensics": {
            "chain_state_file": str(chain_state),
            "pcap_precapture": {"enabled": False},
        },
        "signing": {},
    }
    monkeypatch.setattr(forensics, "get_path", lambda name: str(tmp_path))
    monkeypatch.setattr(forensics, "get_config", lambda: cfg)
    monkeypatch.setattr(forensics, "get_precapture_manager", lambda _cfg: _DummyPrecapture())

    collector = forensics.ForensicsCollector()
    bundle1 = tmp_path / "bundle1.tar.gz"
    bundle1.write_bytes(b"one")
    manifest1 = collector._append_integrity_manifest(bundle1)
    data1 = json.loads(manifest1.read_text(encoding="utf-8"))
    assert data1["artifact"] == "bundle1.tar.gz"
    assert data1["chain_hash"]

    state1 = json.loads(chain_state.read_text(encoding="utf-8"))
    assert state1["last_hash"] == data1["chain_hash"]

    bundle2 = tmp_path / "bundle2.tar.gz"
    bundle2.write_bytes(b"two")
    manifest2 = collector._append_integrity_manifest(bundle2)
    data2 = json.loads(manifest2.read_text(encoding="utf-8"))
    assert data2["previous_hash"] == data1["chain_hash"]

    state2 = json.loads(chain_state.read_text(encoding="utf-8"))
    assert state2["last_hash"] == data2["chain_hash"]
