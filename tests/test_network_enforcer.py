from phantom.response.enforcement import NetworkEnforcer


def test_ip_set_selection() -> None:
    enforcer = NetworkEnforcer()
    assert enforcer._ip_set_name("10.0.0.1") == enforcer.ipv4_set
    assert enforcer._ip_set_name("2001:db8::1") == enforcer.ipv6_set
    assert enforcer._ip_set_name("not-an-ip") is None
