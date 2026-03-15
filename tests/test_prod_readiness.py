"""Тесты утилит prod readiness."""

import yaml

import phantom.core.prod_readiness as prod


def test_parse_kernel_version():
    assert prod._parse_kernel_version("5.10.12-zen") == (5, 10, 12)
    assert prod._parse_kernel_version("4.9") == (4, 9, 0)
    assert prod._parse_kernel_version("n/a") == (0, 0, 0)


def test_summary_counts():
    results = [
        prod.CheckResult("a", "pass", ""),
        prod.CheckResult("b", "warn", ""),
        prod.CheckResult("c", "fail", ""),
    ]
    assert prod._summary(results) == {"pass": 1, "warn": 1, "fail": 1}


def test_check_config_sections(tmp_path):
    cfg = {
        "paths": {"logs_dir": "/tmp", "traps_dir": "/tmp/traps"},
        "sensors": {},
        "orchestrator": {},
        "forensics": {},
        "api": {},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    results: list[prod.CheckResult] = []
    loaded = prod._check_config(results, path)
    assert loaded["paths"]["logs_dir"] == "/tmp"
    assert any(item.name == "config_sections" and item.status == "pass" for item in results)


def test_check_os_kernel_non_linux(monkeypatch):
    results: list[prod.CheckResult] = []
    monkeypatch.setattr(prod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(prod.platform, "release", lambda: "22.0")
    prod._check_os_kernel(results)
    assert results[0].status == "fail"


def test_check_commands_missing(monkeypatch):
    results: list[prod.CheckResult] = []
    monkeypatch.setattr(prod.shutil, "which", lambda _cmd: None)
    prod._check_commands(results)
    assert results[0].status == "fail"


def test_check_service_file_caps(tmp_path):
    results: list[prod.CheckResult] = []
    path = tmp_path / "phantom.service"
    path.write_text(
        "[Service]\n"
        "CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_PTRACE CAP_KILL\n",
        encoding="utf-8",
    )
    prod._check_service_file(results, path)
    assert results[0].status == "pass"
