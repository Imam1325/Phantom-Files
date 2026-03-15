"""Тесты загрузчика манифеста ловушек."""

import yaml

from phantom.factory.manifest import ManifestLoader


def _write_manifest(tmp_path, data) -> str:
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


def test_manifest_loader_valid(tmp_path):
    path = _write_manifest(
        tmp_path,
        {
            "traps": [
                {
                    "id": "trap-1",
                    "template": "templates/cred.j2",
                    "output": "creds/aws/credentials",
                    "category": "credentials",
                    "format": "text",
                    "priority": "high",
                }
            ]
        },
    )
    loader = ManifestLoader(path)
    tasks = loader.load_tasks()
    assert len(tasks) == 1
    assert tasks[0].trap_id == "trap-1"


def test_manifest_loader_rejects_bad_format(tmp_path):
    path = _write_manifest(
        tmp_path,
        {"traps": [{"id": "trap", "template": "t", "output": "o", "format": "exe"}]},
    )
    loader = ManifestLoader(path)
    tasks = loader.load_tasks()
    assert tasks == []


def test_manifest_loader_blocks_absolute_output(tmp_path):
    path = _write_manifest(
        tmp_path,
        {"traps": [{"id": "trap", "template": "t", "output": "/etc/passwd", "format": "text"}]},
    )
    loader = ManifestLoader(path)
    tasks = loader.load_tasks()
    assert tasks == []


def test_manifest_loader_blocks_path_traversal(tmp_path):
    path = _write_manifest(
        tmp_path,
        {"traps": [{"id": "trap", "template": "../t", "output": "a", "format": "text"}]},
    )
    loader = ManifestLoader(path)
    tasks = loader.load_tasks()
    assert tasks == []
