"""
tests/test_topology.py — юнит-тесты.
Запуск: pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from model import (Device, Interface, NetworkTopology,
                   DEVICE_TYPES, normalize_mac)
from analyzer import (classify_by_ports, classify_by_keywords,
                      parse_snmp_services)


# ════════════════════════════════════════════════════════════════════════
# normalize_mac
# ════════════════════════════════════════════════════════════════════════

class TestNormalizeMAC:
    def test_linux(self):    assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    def test_windows(self):  assert normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"
    def test_cisco(self):    assert normalize_mac("aabb.ccdd.eeff")    == "AA:BB:CC:DD:EE:FF"
    def test_nodel(self):    assert normalize_mac("aabbccddeeff")      == "AA:BB:CC:DD:EE:FF"
    def test_empty(self):    assert normalize_mac("") == ""
    def test_bad(self):      assert normalize_mac("gg:hh:ii:jj:kk:ll") == ""
    def test_short(self):    assert normalize_mac("aa:bb:cc") == ""
    def test_idempotent(self):
        n = normalize_mac("AA:BB:CC:DD:EE:FF")
        assert normalize_mac(n) == n
    def test_same_result(self):
        results = {normalize_mac(m) for m in [
            "00:11:22:33:44:55", "00-11-22-33-44-55",
            "0011.2233.4455",    "001122334455"]}
        assert len(results) == 1


# ════════════════════════════════════════════════════════════════════════
# Расширенные типы устройств
# ════════════════════════════════════════════════════════════════════════

class TestExtendedTypes:
    def test_all_new_types_present(self):
        for t in ["windows_server", "linux_server", "windows_endpoint",
                  "linux_endpoint", "printer"]:
            assert t in DEVICE_TYPES, f"{t} не найден в DEVICE_TYPES"

    def test_labels_exist(self):
        from model import DEVICE_TYPE_LABELS
        for t in DEVICE_TYPES:
            assert t in DEVICE_TYPE_LABELS, f"Нет метки для {t}"

    def test_colors_exist(self):
        from model import TYPE_COLORS
        for t in DEVICE_TYPES:
            assert t in TYPE_COLORS, f"Нет цвета для {t}"


# ════════════════════════════════════════════════════════════════════════
# classify_by_keywords
# ════════════════════════════════════════════════════════════════════════

class TestClassifyKeywords:
    def test_windows_server(self):
        assert classify_by_keywords("Windows Server 2019")  == "windows_server"
    def test_windows_server_2022(self):
        assert classify_by_keywords("Microsoft Windows Server 2022") == "windows_server"
    def test_linux_server_ubuntu(self):
        assert classify_by_keywords("Ubuntu Server 22.04 LTS") == "linux_server"
    def test_linux_server_centos(self):
        assert classify_by_keywords("CentOS Linux 7")        == "linux_server"
    def test_linux_server_rhel(self):
        assert classify_by_keywords("Red Hat Enterprise Linux 8") == "linux_server"
    def test_windows_10(self):
        assert classify_by_keywords("Windows 10 Pro")        == "windows_endpoint"
    def test_windows_11(self):
        assert classify_by_keywords("Windows 11 Home")       == "windows_endpoint"
    def test_macos(self):
        assert classify_by_keywords("Darwin 23.0.0 macOS")   == "linux_endpoint"
    def test_linux_desktop(self):
        assert classify_by_keywords("Ubuntu Desktop 22.04")  == "linux_endpoint"
    def test_cisco_router(self):
        assert classify_by_keywords("Cisco IOS Software 15.2") == "router"
    def test_mikrotik(self):
        assert classify_by_keywords("MikroTik RouterOS 6.49") == "router"
    def test_pfsense(self):
        assert classify_by_keywords("pfSense 2.7.0-RELEASE")  == "firewall"
    def test_hp_switch(self):
        assert classify_by_keywords("HP ProCurve Switch 2810") == "switch"
    def test_printer_laserjet(self):
        assert classify_by_keywords("HP LaserJet MFP")         == "printer"
    def test_printer_kyocera(self):
        assert classify_by_keywords("Kyocera ECOSYS P3145dn")  == "printer"
    def test_unknown(self):
        assert classify_by_keywords("XYZ Device 12345") is None


# ════════════════════════════════════════════════════════════════════════
# classify_by_ports
# ════════════════════════════════════════════════════════════════════════

class TestClassifyPorts:
    def test_printer_jetdirect(self):  assert classify_by_ports([9100]) == "printer"
    def test_printer_lpr(self):        assert classify_by_ports([515])  == "printer"
    def test_mssql(self):              assert classify_by_ports([1433]) == "windows_server"
    def test_postgresql(self):         assert classify_by_ports([5432]) == "linux_server"
    def test_redis(self):              assert classify_by_ports([6379]) == "linux_server"
    def test_rdp(self):
        r = classify_by_ports([3389])
        assert r in ("windows_endpoint", "windows_server")
    def test_winrm(self):              assert classify_by_ports([5985]) == "windows_server"
    def test_smtp(self):
        r = classify_by_ports([25])
        assert r in ("linux_server", "windows_server")
    def test_bgp(self):                assert classify_by_ports([179]) == "router"
    def test_empty(self):              assert classify_by_ports([]) is None
    def test_unknown_ports(self):      assert classify_by_ports([54321]) is None
    def test_mixed_web(self):
        r = classify_by_ports([80, 443])
        assert r is not None


# ════════════════════════════════════════════════════════════════════════
# parse_snmp_services
# ════════════════════════════════════════════════════════════════════════

class TestSNMPServices:
    def test_router(self):   assert parse_snmp_services("4")   == "router"
    def test_router_l3(self):assert parse_snmp_services("6")   == "router"
    def test_switch(self):   assert parse_snmp_services("2")   == "switch"
    def test_server(self):   assert parse_snmp_services("64")  == "linux_server"
    def test_zero(self):     assert parse_snmp_services("0")   is None
    def test_invalid(self):  assert parse_snmp_services("abc") is None
    def test_empty(self):    assert parse_snmp_services("")    is None


# ════════════════════════════════════════════════════════════════════════
# Device / Interface
# ════════════════════════════════════════════════════════════════════════

class TestDevice:
    def test_no_duplicate_in_init(self):
        dev = Device(ip="1.2.3.4",
                     interfaces=[Interface(ip="1.2.3.4", subnet="1.0.0.0/8")])
        assert len(dev.interfaces) == 1

    def test_add_interface(self):
        dev = Device(ip="1.2.3.4")
        dev.add_interface("10.0.0.1", subnet="10.0.0.0/8")
        assert "10.0.0.1" in dev.all_ips()

    def test_no_add_duplicate(self):
        dev = Device(ip="1.2.3.4")
        dev.add_interface("1.2.3.4")
        assert len(dev.interfaces) == 1

    def test_multihomed_label_star(self):
        dev = Device(ip="1.2.3.4", is_multihomed=True, device_type="router")
        dev.add_interface("10.0.0.1")
        assert "★" in dev.label()

    def test_single_label_no_star(self):
        dev = Device(ip="1.2.3.4", device_type="endpoint")
        assert "★" not in dev.label()

    def test_label_shows_type_label(self):
        from model import DEVICE_TYPE_LABELS
        dev = Device(ip="1.2.3.4", device_type="windows_server")
        assert DEVICE_TYPE_LABELS["windows_server"] in dev.label()

    def test_serialization_roundtrip(self):
        dev = Device(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF",
                     device_type="linux_server", node_id="x1",
                     subnet="192.168.1.0/24", is_multihomed=True,
                     position=(100.0, 200.0))
        dev.add_interface("10.0.0.1", subnet="10.0.0.0/24", iface_name="eth1")
        r = Device.from_dict(dev.to_dict())
        assert r.ip          == dev.ip
        assert r.device_type == dev.device_type
        assert r.is_multihomed
        assert "10.0.0.1" in r.all_ips()
        assert r.position    == dev.position


# ════════════════════════════════════════════════════════════════════════
# merge_by_mac
# ════════════════════════════════════════════════════════════════════════

class TestMergeByMAC:
    def _base_topo(self):
        topo = NetworkTopology()
        r1 = Device(ip="192.168.1.1", mac="aa:bb:cc:00:00:01",
                    device_type="router",  node_id="r1")
        r2 = Device(ip="10.0.0.1",    mac="AA-BB-CC-00-00-01",
                    device_type="unknown", node_id="r2")
        ep = Device(ip="192.168.1.10", mac="00:11:22:33:44:55",
                    device_type="endpoint", node_id="ep")
        for d in [r1, r2, ep]: topo.add_device(d)
        topo.add_link("r1", "ep"); topo.add_link("r2", "ep")
        return topo, r1, r2, ep

    def test_count(self):
        topo, *_ = self._base_topo()
        assert topo.merge_by_mac() == 1

    def test_devices_reduced(self):
        topo, *_ = self._base_topo()
        topo.merge_by_mac()
        assert len(topo.devices) == 2

    def test_multihomed_flag(self):
        topo, *_ = self._base_topo()
        topo.merge_by_mac()
        r = topo.get_by_ip("192.168.1.1")
        assert r.is_multihomed

    def test_ips_transferred(self):
        topo, *_ = self._base_topo()
        topo.merge_by_mac()
        r = topo.get_by_ip("192.168.1.1")
        assert "10.0.0.1" in r.all_ips()

    def test_edges_kept(self):
        topo, *_ = self._base_topo()
        topo.merge_by_mac()
        r  = topo.get_by_ip("192.168.1.1")
        ep = topo.get_by_ip("192.168.1.10")
        assert topo.graph.has_edge(r.node_id, ep.node_id)

    def test_no_merge_diff_mac(self):
        topo = NetworkTopology()
        topo.add_device(Device(ip="1.1.1.1", mac="aa:00:00:00:00:01", node_id="a"))
        topo.add_device(Device(ip="1.1.1.2", mac="aa:00:00:00:00:02", node_id="b"))
        assert topo.merge_by_mac() == 0

    def test_no_merge_empty_mac(self):
        topo = NetworkTopology()
        topo.add_device(Device(ip="1.1.1.1", node_id="a"))
        topo.add_device(Device(ip="1.1.1.2", node_id="b"))
        assert topo.merge_by_mac() == 0

    def test_cisco_mac_format(self):
        topo = NetworkTopology()
        topo.add_device(Device(ip="1.1.1.1", mac="aabb.ccdd.ee01", node_id="a"))
        topo.add_device(Device(ip="1.1.1.2", mac="AA:BB:CC:DD:EE:01", node_id="b"))
        assert topo.merge_by_mac() == 1

    def test_three_way_merge(self):
        topo = NetworkTopology()
        mac  = "aa:bb:cc:dd:ee:ff"
        for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
            topo.add_device(Device(ip=ip, mac=mac, node_id=f"n{i}"))
        assert topo.merge_by_mac() == 1
        assert len(topo.devices)   == 1


# ════════════════════════════════════════════════════════════════════════
# merge_devices / split_device
# ════════════════════════════════════════════════════════════════════════

class TestManualOps:
    def _topo(self):
        topo = NetworkTopology()
        a  = Device(ip="192.168.1.1", device_type="router",   node_id="a")
        b  = Device(ip="10.0.0.1",    device_type="server",   node_id="b")
        ep = Device(ip="192.168.1.50", device_type="endpoint", node_id="ep")
        for d in [a, b, ep]: topo.add_device(d)
        topo.add_link("b", "ep")
        return topo, a, b, ep

    def test_merge_success(self):
        topo, a, b, _ = self._topo()
        assert topo.merge_devices("a", "b") is True
        assert "b" not in topo.devices
        assert a.is_multihomed

    def test_merge_ips(self):
        topo, a, b, _ = self._topo()
        topo.merge_devices("a", "b")
        assert "10.0.0.1" in a.all_ips()

    def test_merge_edges(self):
        topo, a, b, ep = self._topo()
        topo.merge_devices("a", "b")
        assert topo.graph.has_edge("a", "ep")

    def test_merge_same_returns_false(self):
        topo, a, *_ = self._topo()
        assert topo.merge_devices("a", "a") is False

    def test_split_creates_node(self):
        topo = NetworkTopology()
        dev  = Device(ip="192.168.1.1", device_type="router",
                      node_id="r1", subnet="192.168.1.0/24")
        dev.add_interface("10.0.0.1", subnet="10.0.0.0/24")
        dev.is_multihomed = True
        topo.add_device(dev)
        new_id = topo.split_device("r1", "10.0.0.1")
        assert new_id is not None
        assert new_id in topo.devices

    def test_split_removes_ip(self):
        topo = NetworkTopology()
        dev  = Device(ip="192.168.1.1", node_id="r1")
        dev.add_interface("10.0.0.1")
        topo.add_device(dev)
        topo.split_device("r1", "10.0.0.1")
        assert "10.0.0.1" not in dev.all_ips()

    def test_split_only_ip_fails(self):
        topo = NetworkTopology()
        dev  = Device(ip="192.168.1.1", node_id="r1")
        topo.add_device(dev)
        assert topo.split_device("r1", "192.168.1.1") is None

    def test_split_missing_ip_fails(self):
        topo = NetworkTopology()
        dev  = Device(ip="192.168.1.1", node_id="r1")
        dev.add_interface("10.0.0.1")
        topo.add_device(dev)
        assert topo.split_device("r1", "99.99.99.99") is None


# ════════════════════════════════════════════════════════════════════════
# build_from_multi_subnet
# ════════════════════════════════════════════════════════════════════════

class TestMultiSubnet:
    def test_merge_across_subnets(self):
        topo = NetworkTopology()
        r1   = Device(ip="192.168.1.1", mac="aa:00:00:00:00:01",
                      device_type="router",  node_id="r1")
        r2   = Device(ip="10.0.0.1",    mac="aa:00:00:00:00:01",
                      device_type="unknown", node_id="r2")
        topo.build_from_multi_subnet([
            ("192.168.1.0/24", [r1], None),
            ("10.0.0.0/24",    [r2], None),
        ])
        assert len(topo.devices) == 1
        dev = list(topo.devices.values())[0]
        assert dev.is_multihomed

    def test_no_false_merge(self):
        topo = NetworkTopology()
        topo.build_from_multi_subnet([
            ("192.168.1.0/24",
             [Device(ip="192.168.1.1", mac="aa:00:00:00:00:01", node_id="a")],
             None),
            ("10.0.0.0/24",
             [Device(ip="10.0.0.1",    mac="bb:00:00:00:00:02", node_id="b")],
             None),
        ])
        assert len(topo.devices) == 2

    def test_subnets_tagged(self):
        topo = NetworkTopology()
        topo.build_from_multi_subnet([
            ("192.168.1.0/24",
             [Device(ip="192.168.1.1", mac="aa:00:00:00:00:01", node_id="r1")],
             None),
        ])
        dev = topo.get_by_ip("192.168.1.1")
        assert any(i.subnet == "192.168.1.0/24" for i in dev.interfaces)

    def test_json_roundtrip(self, tmp_path):
        topo = NetworkTopology()
        topo.build_from_multi_subnet([
            ("192.168.1.0/24",
             [Device(ip="192.168.1.1", mac="aa:00:00:00:00:01",
                     device_type="router", node_id="r1")], None),
            ("10.0.0.0/24",
             [Device(ip="10.0.0.1",    mac="aa:00:00:00:00:01",
                     device_type="router", node_id="r2")], None),
        ])
        path = str(tmp_path / "t.json")
        topo.save_json(path)
        topo2 = NetworkTopology()
        topo2.load_json(path)
        multi = [d for d in topo2.devices.values() if d.is_multihomed]
        assert len(multi) == 1
        assert len(multi[0].all_ips()) >= 2


# ════════════════════════════════════════════════════════════════════════
# CLI-таблица: * для мультиинтерфейсных
# ════════════════════════════════════════════════════════════════════════

class TestCLITable:
    def test_star_present(self, capsys):
        import types, sys
        fake_gui = types.ModuleType("gui")
        fake_gui.run_gui = lambda t: None
        sys.modules.setdefault("gui", fake_gui)
        from net_topology import print_cli_table
        topo = NetworkTopology()
        dev  = Device(ip="192.168.1.1", device_type="router",
                      node_id="r1", is_multihomed=True)
        dev.add_interface("10.0.0.1", subnet="10.0.0.0/24")
        topo.add_device(dev)
        print_cli_table(topo)
        out = capsys.readouterr().out
        assert "*" in out

    def test_no_star_for_single(self, capsys):
        import types, sys
        fake_gui = types.ModuleType("gui")
        fake_gui.run_gui = lambda t: None
        sys.modules.setdefault("gui", fake_gui)
        from net_topology import print_cli_table
        topo = NetworkTopology()
        topo.add_device(Device(ip="1.2.3.4", device_type="endpoint",
                               node_id="ep1"))
        print_cli_table(topo)
        out = capsys.readouterr().out
        for line in out.splitlines():
            if "1.2.3.4" in line:
                assert not line.startswith("*")
