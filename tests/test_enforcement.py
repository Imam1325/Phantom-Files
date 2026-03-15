"""Тесты enforcement (PID-валидация, IP-наборы)."""

from pathlib import Path

from phantom.response.enforcement import CommandResult, NetworkEnforcer, ProcessEnforcer, CgroupEbpfIsolator


# ---------- PID-валидация в ProcessEnforcer ----------

def test_process_enforcer_rejects_pid_0():
    pe = ProcessEnforcer()
    assert pe._send_signal(0, __import__("signal").SIGSTOP) is False


def test_process_enforcer_rejects_pid_1():
    pe = ProcessEnforcer()
    assert pe._send_signal(1, __import__("signal").SIGKILL) is False


def test_process_enforcer_rejects_negative_pid():
    pe = ProcessEnforcer()
    assert pe._send_signal(-1, __import__("signal").SIGSTOP) is False


def test_process_enforcer_nonexistent_pid():
    pe = ProcessEnforcer()
    # PID 999999999 не должен существовать
    assert pe._send_signal(999999999, __import__("signal").SIGSTOP) is False


# ---------- PID-валидация в CgroupEbpfIsolator ----------

def test_cgroup_rejects_pid_0():
    iso = CgroupEbpfIsolator()
    assert iso.isolate_pid(0) is False


def test_cgroup_rejects_pid_1():
    iso = CgroupEbpfIsolator()
    assert iso.isolate_pid(1) is False


def test_cgroup_rejects_negative_pid():
    iso = CgroupEbpfIsolator()
    assert iso.isolate_pid(-100) is False


# ---------- IP set selection ----------

def test_ipv4_set_selection():
    ne = NetworkEnforcer()
    assert ne._ip_set_name("10.0.0.1") == ne.ipv4_set


def test_ipv6_set_selection():
    ne = NetworkEnforcer()
    assert ne._ip_set_name("2001:db8::1") == ne.ipv6_set


def test_invalid_ip_returns_none():
    ne = NetworkEnforcer()
    assert ne._ip_set_name("not-an-ip") is None


def test_ip_loopback_v4():
    ne = NetworkEnforcer()
    assert ne._ip_set_name("127.0.0.1") == ne.ipv4_set


def test_ip_loopback_v6():
    ne = NetworkEnforcer()
    assert ne._ip_set_name("::1") == ne.ipv6_set


# ---------- UID resolution (мок /proc недоступен в тестовой среде) ----------

def test_pid_uid_nonexistent():
    ne = NetworkEnforcer()
    assert ne._pid_uid(999999999) is None


def test_ensure_base_idempotent(monkeypatch):
    calls = []

    def _fake_run_nft(self, args, tolerate_errors):  # noqa: ANN001
        calls.append(tuple(args))
        return CommandResult(ok=True)

    monkeypatch.setattr(NetworkEnforcer, "_run_nft", _fake_run_nft)
    ne = NetworkEnforcer()
    ne._ensure_base()
    first = len(calls)
    ne._ensure_base()
    assert len(calls) == first


def test_pid_starttime_parsing(monkeypatch):
    iso = CgroupEbpfIsolator()
    text = "1234 (cmd) " + " ".join(["S"] + [str(i) for i in range(1, 25)])

    def _fake_read_text(self, *args, **kwargs):  # noqa: ANN001
        return text

    monkeypatch.setattr(Path, "read_text", _fake_read_text)
    assert iso._pid_starttime(123) == 19
