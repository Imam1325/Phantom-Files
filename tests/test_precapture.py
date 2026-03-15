"""Тесты модуля предзахвата пакетов (telemetry/precapture.py)."""

import struct
from pathlib import Path

from phantom.telemetry.precapture import (
    _extract_ports,
    PreCaptureManager,
)


# ---------- _extract_ports: IPv4 TCP ----------

def test_extract_ports_ipv4_tcp():
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ipv4 = bytes.fromhex("4500002800010000400600000a0000010a000002")
    tcp = bytes.fromhex("1f90005000000000000000005002000000000000")
    packet = eth + ipv4 + tcp
    src, dst = _extract_ports(packet)
    assert src == 8080
    assert dst == 80


# ---------- _extract_ports: IPv4 UDP ----------

def test_extract_ports_ipv4_udp():
    eth = bytes.fromhex("00112233445566778899aabb0800")
    # IHL=5, proto=17 (UDP)
    ipv4 = bytes.fromhex("4500002800010000401100000a0000010a000002")
    udp = bytes.fromhex("00350050001c0000")  # src=53, dst=80
    packet = eth + ipv4 + udp
    src, dst = _extract_ports(packet)
    assert src == 53
    assert dst == 80


# ---------- _extract_ports: IPv6 TCP ----------

def test_extract_ports_ipv6_tcp():
    eth = bytes.fromhex("00112233445566778899aabb86dd")
    # IPv6: version=6, payload_len=20, next_header=6 (TCP), hop_limit=64
    ipv6 = bytes.fromhex(
        "60000000001406400000000000000000000000000000000100000000000000000000000000000002"
    )
    tcp = bytes.fromhex("01bb005000000000000000005002000000000000")  # src=443, dst=80
    packet = eth + ipv6 + tcp
    src, dst = _extract_ports(packet)
    assert src == 443
    assert dst == 80


# ---------- _extract_ports: IPv6 UDP ----------

def test_extract_ports_ipv6_udp():
    eth = bytes.fromhex("00112233445566778899aabb86dd")
    # next_header=17 (UDP)
    ipv6 = bytes.fromhex(
        "60000000000811400000000000000000000000000000000100000000000000000000000000000002"
    )
    udp = bytes.fromhex("00350050000800000000000000000000")  # src=53, dst=80
    packet = eth + ipv6 + udp
    src, dst = _extract_ports(packet)
    assert src == 53
    assert dst == 80


# ---------- _extract_ports: VLAN (802.1Q) ----------

def test_extract_ports_vlan():
    """802.1Q VLAN tag (EtherType 0x8100) перед реальным EtherType."""
    eth = bytes.fromhex("00112233445566778899aabb8100")
    vlan_tag = bytes.fromhex("00640800")  # VLAN id=100, inner EtherType=0x0800
    ipv4 = bytes.fromhex("4500002800010000400600000a0000010a000002")
    tcp = bytes.fromhex("1f90005000000000000000005002000000000000")
    packet = eth + vlan_tag + ipv4 + tcp
    src, dst = _extract_ports(packet)
    assert src == 8080
    assert dst == 80


# ---------- _extract_ports: edge cases ----------

def test_extract_ports_too_short():
    assert _extract_ports(b"") == (None, None)
    assert _extract_ports(b"\x00" * 10) == (None, None)


def test_extract_ports_non_ip():
    """ARP (EtherType 0x0806) → (None, None)."""
    packet = bytes.fromhex("00112233445566778899aabb0806") + b"\x00" * 28
    src, dst = _extract_ports(packet)
    assert src is None
    assert dst is None


def test_extract_ports_icmp():
    """ICMP (proto=1) — не TCP/UDP → (None, None)."""
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ipv4 = bytes.fromhex("4500002800010000400100000a0000010a000002")
    icmp = bytes.fromhex("0800000000000000")
    packet = eth + ipv4 + icmp
    src, dst = _extract_ports(packet)
    assert src is None
    assert dst is None


def test_extract_ports_ipv4_truncated_l4():
    """IPv4 пакет без L4 данных."""
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ipv4 = bytes.fromhex("4500002800010000400600000a0000010a000002")
    packet = eth + ipv4  # нет TCP-заголовка
    src, dst = _extract_ports(packet)
    assert src is None
    assert dst is None


# ---------- PreCaptureManager ----------

def test_manager_default_status():
    mgr = PreCaptureManager()
    status = mgr.status()
    assert status["mode"] == "disabled"
    assert status["running"] is False
    assert status["max_buffer_mb"] == 64
    assert status["pre_seconds"] == 30.0
    assert status["post_seconds"] == 30.0


def test_manager_configure():
    mgr = PreCaptureManager()
    mgr.configure({
        "forensics": {
            "pcap_precapture": {
                "enabled": True,
                "max_buffer_mb": 32,
                "pre_seconds": 10,
                "post_seconds": 15,
                "snaplen": 1500,
                "capture_ports": [80, 443],
            }
        }
    })
    assert mgr._max_buffer_mb == 32
    assert mgr._pre_seconds == 10.0
    assert mgr._post_seconds == 15.0
    assert mgr._snaplen == 1500
    assert mgr._ports == {80, 443}


def test_manager_configure_disabled():
    mgr = PreCaptureManager()
    mgr.configure({"forensics": {"pcap_precapture": {"enabled": False}}})
    mgr.start()
    assert mgr._mode == "disabled"


def test_manager_configure_min_values():
    """Минимальные пороги для snaplen и max_buffer_mb."""
    mgr = PreCaptureManager()
    mgr.configure({
        "forensics": {
            "pcap_precapture": {
                "snaplen": 10,       # min 256
                "max_buffer_mb": 1,  # min 8
            }
        }
    })
    assert mgr._snaplen == 256
    assert mgr._max_buffer_mb == 8


def test_manager_stop_without_start():
    mgr = PreCaptureManager()
    mgr.stop()  # Не бросает
    assert mgr._running is False


def test_manager_packet_allowed_no_ports():
    """Без фильтра портов — всё пропускается."""
    mgr = PreCaptureManager()
    mgr._ports = set()
    assert mgr._packet_allowed(b"\x00" * 100) is True


def test_manager_packet_allowed_with_ports():
    """Фильтр портов: пропускает только указанные."""
    mgr = PreCaptureManager()
    mgr._ports = {8080}
    # Пакет с src=8080
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ipv4 = bytes.fromhex("4500002800010000400600000a0000010a000002")
    tcp = bytes.fromhex("1f90005000000000000000005002000000000000")
    assert mgr._packet_allowed(eth + ipv4 + tcp) is True


def test_manager_packet_blocked_wrong_port():
    mgr = PreCaptureManager()
    mgr._ports = {9999}
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ipv4 = bytes.fromhex("4500002800010000400600000a0000010a000002")
    tcp = bytes.fromhex("1f90005000000000000000005002000000000000")
    assert mgr._packet_allowed(eth + ipv4 + tcp) is False


def test_manager_write_pcap(tmp_path: Path):
    """_write_pcap создаёт валидный PCAP-файл."""
    mgr = PreCaptureManager()
    packets = [
        (1700000000.123456, b"\x00" * 64),
        (1700000001.654321, b"\xff" * 128),
    ]
    output = str(tmp_path / "capture.pcap")
    mgr._write_pcap(output, packets)
    data = Path(output).read_bytes()
    # Проверяем magic number
    magic = struct.unpack("<I", data[:4])[0]
    assert magic == 0xA1B2C3D4
    # Проверяем major/minor version
    major, minor = struct.unpack("<HH", data[4:8])
    assert major == 2
    assert minor == 4


def test_manager_snapshot():
    mgr = PreCaptureManager()
    # Заполняем буфер напрямую
    mgr._buffer.append((100.0, b"a"))
    mgr._buffer.append((200.0, b"b"))
    mgr._buffer.append((300.0, b"c"))
    result = mgr._snapshot(150.0, 250.0)
    assert len(result) == 1
    assert result[0][1] == b"b"


def test_manager_snapshot_empty_range():
    mgr = PreCaptureManager()
    mgr._buffer.append((100.0, b"a"))
    result = mgr._snapshot(200.0, 300.0)
    assert result == []
