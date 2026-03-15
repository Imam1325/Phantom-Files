import json
from pathlib import Path

from phantom.factory.manager import TrapFactory


def test_template_globals_and_datasets_are_merged(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("traps: []\n", encoding="utf-8")

    ds_yaml = tmp_path / "global.yaml"
    ds_yaml.write_text("nested:\n  a: 1\n  b: 2\n", encoding="utf-8")
    ds_json = tmp_path / "global.json"
    ds_json.write_text(json.dumps({"nested": {"b": 3, "c": 4}, "env": "prod"}), encoding="utf-8")

    config = {
        "paths": {
            "traps_dir": str(tmp_path / "traps"),
            "templates": str(tmp_path / "templates"),
            "user_templates_dir": str(tmp_path / "user_templates"),
            "manifest": str(manifest),
        },
        "templates": {
            "globals": {"env": "dev", "owner": "security"},
            "datasets": [str(ds_yaml), str(ds_json)],
        },
    }

    factory = TrapFactory(config)
    assert factory.base_context["owner"] == "security"
    assert factory.base_context["env"] == "prod"
    assert factory.base_context["nested"]["a"] == 1
    assert factory.base_context["nested"]["b"] == 3
    assert factory.base_context["nested"]["c"] == 4
