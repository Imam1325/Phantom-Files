"""Тесты bootstrap-процедуры."""

import grp
import os
import pwd

import pytest

from phantom.core.bootstrap import BootstrapError, _iter_bootstrap_dirs, bootstrap, ensure_dir


def test_ensure_dir_rejects_symlink(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported on this platform")

    user = pwd.getpwuid(os.geteuid()).pw_name
    group = grp.getgrgid(os.getegid()).gr_name
    with pytest.raises(BootstrapError):
        ensure_dir(str(link), owner_user=user, owner_group=group, mode=0o750)


def test_bootstrap_dry_run_returns_actions(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        "paths:\n"
        "  logs_dir: /var/log/phantom\n"
        "  traps_dir: /var/lib/phantom/traps\n",
        encoding="utf-8",
    )
    actions = bootstrap(config_path=str(cfg_path), dry_run=True)
    assert any("ensure group: phantom-user" in item for item in actions)
    assert any("ensure dir: /var/lib/phantom" in item for item in actions)


def test_iter_bootstrap_dirs_includes_chain_state():
    cfg = {
        "paths": {
            "logs_dir": "/var/log/phantom",
            "traps_dir": "/var/lib/phantom/traps",
            "trap_registry_file": "/var/lib/phantom/trap_registry.json",
        },
        "forensics": {"chain_state_file": "/var/lib/phantom/evidence/chain_state.json"},
    }
    dirs = _iter_bootstrap_dirs(cfg)
    assert "/var/log/phantom" in dirs
    assert "/var/lib/phantom/traps" in dirs
    assert "/var/lib/phantom" in dirs
    assert "/var/lib/phantom/evidence" in dirs
