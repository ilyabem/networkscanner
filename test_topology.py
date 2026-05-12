"""
tests/test_topology.py — юнит-тесты.

Запуск:
    pytest tests/ -v

ДОРАБОТКА: добавлены тесты на:
  - normalize_mac (разные форматы, граничные случаи)
  - merge_by_mac (дубли, разные форматы MAC, пустые данные, коллизии)
  - merge_devices / split_device (ручные операции)
  - build_from_multi_subnet (несколько подсетей)
  - CLI-таблица (мультиинтерфейсные помечены *)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from model import (
    Device, Interface, NetworkTopology,
    DEVICE_TYPES, normalize_mac,
)
from analyzer import classify_by_ports, parse_snmp_services, DeviceAnalyzer


# ════════════════════════════════════════════════════════════════════════════
# normalize_mac
# ════════════════════════════════════════════════════════════════════════════

class TestNormalizeMAC:
    def test_linux_format(self):
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_windows_format(self):
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"

    def test_cisco_format(self):
        assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"

    def test_no_separator(self):
        assert normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"

    def test_mixed_case(self):
        assert normalize_mac("Aa:Bb:Cc:Dd:Ee:Ff") == "AA:BB:CC:DD:EE:FF"

    def test_empty_string(self):
        assert normalize_mac("") == ""

    def test_none_like_empty(self):
        assert normalize_mac("") == ""

    def test_too_short(self):
        assert normalize_mac("aa:bb:cc") == ""

    def test_invalid_chars(self):
        assert normalize_mac("gg:hh:ii:jj:kk:ll") == ""

    def test_idempotent(self):
        norm = normalize_mac("AA:BB:CC:DD:EE:FF")
        assert normalize_mac(norm) == norm

    def test_same_mac_different_formats(self):
        """Разные форматы одного MAC дают одинаковый результат."""
        formats = [
            "00:11:22:33:44:55",
            "00-11-22-33-44-55",
            "0011.2233.4455",
            "001122334455",
        ]
        results = {normalize_mac(m) for m in formats}
        assert len(results) == 1  # все форматы → один результат


# ════════════════════════════════════════════════════════════════════════════
# Interface и Device с несколькими интерфейсами
# ════════════════════════════════════════════════════════════════════════════

class TestInterface:
    def test_to_from_dict(self):
        iface = Interface(ip="10.0.0.1", subnet="10.0.0.0/24", iface_name="eth1")
        restored = Interface.from_dict(iface.to_dict())
        assert restored.ip         == iface.ip
        assert restored.subnet     == iface.subnet
        assert restored.iface_name == iface.iface_name

class TestDeviceMultiHomed:
    def _make_multi(self) -> Device:
        dev = Device(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF",
                     subnet="192.168.1.0/24", device_type="router", node_id="r1")
        dev.add_interface("10.0.0.1", subnet="10.0.0.0/24", iface_name="eth1")
        dev.is_multihomed = True
        return dev

    def test_all_ips(self):
        dev = self._make_multi()
        assert "192.168.1.1" in dev.all_ips()
        assert "10.0.0.1"    in dev.all_ips()

    def test_no_duplicate_interfaces(self):
        dev = self._make_multi()
        before = len(dev.interfaces)
        dev.add_interface("192.168.1.1")   # уже есть
        assert len(dev.interfaces) == before

    def test_label_contains_star(self):
        dev = self._make_multi()
        assert "★" in dev.label()

    def test_label_no_star_single(self):
        dev = Device(ip="1.2.3.4", device_type="endpoint")
        assert "★" not in dev.label()

    def test_interfaces_label(self):
        dev = self._make_multi()
        lbl = dev.interfaces_label()
        assert "192.168.1.1" in lbl
        assert "10.0.0.1"    in lbl

    def test_serialization_round_trip(self):
        dev = self._make_multi()
        restored = Device.from_dict(dev.to_dict())
        assert len(restored.interfaces)  == len(dev.interfaces)
        assert restored.is_multihomed    == dev.is_multihomed
        assert "10.0.0.1" in restored.all_ips()


# ════════════════════════════════════════════════════════════════════════════
# merge_by_mac
# ════════════════════════════════════════════════════════════════════════════

class TestMergeByMAC:

    def _make_topo_with_dup_mac(self) -> NetworkTopology:
        """Топология с двумя узлами, имеющими одинаковый MAC в разных форматах."""
        topo = NetworkTopology()
        r1 = Device(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01",
                    device_type="router",   subnet="192.168.1.0/24", node_id="r1")
        r2 = Device(ip="10.0.0.1",    mac="AA-BB-CC-DD-EE-01",   # тот же MAC, другой формат
                    device_type="unknown",  subnet="10.0.0.0/24",   node_id="r2")
        ep = Device(ip="192.168.1.10", mac="00:11:22:33:44:55",
                    device_type="endpoint", subnet="192.168.1.0/24", node_id="ep1")
        for dev in [r1, r2, ep]:
            topo.add_device(dev)
        topo.add_link("r1", "ep1", label="ARP")
        topo.add_link("r2", "ep1", label="ARP")
        return topo

    def test_merge_count(self):
        topo = self._make_topo_with_dup_mac()
        count = topo.merge_by_mac()
        assert count == 1   # одна группа дублей

    def test_devices_reduced(self):
        topo = self._make_topo_with_dup_mac()
        topo.merge_by_mac()
        assert len(topo.devices) == 2   # роутер + endpoint

    def test_merged_node_is_multihomed(self):
        topo = self._make_topo_with_dup_mac()
        topo.merge_by_mac()
        router = topo.get_by_ip("192.168.1.1")
        assert router is not None
        assert router.is_multihomed is True

    def test_all_ips_present_after_merge(self):
        topo = self._make_topo_with_dup_mac()
        topo.merge_by_mac()
        router = topo.get_by_ip("192.168.1.1") or topo.get_by_ip("10.0.0.1")
        assert router is not None
        all_ips = router.all_ips()
        assert "192.168.1.1" in all_ips
        assert "10.0.0.1"    in all_ips

    def test_edges_redirected(self):
        """Рёбра удалённого дубля должны перейти к главному узлу."""
        topo = self._make_topo_with_dup_mac()
        topo.merge_by_mac()
        # После слияния роутер должен быть соединён с endpoint
        router = topo.get_by_ip("192.168.1.1") or topo.get_by_ip("10.0.0.1")
        ep     = topo.get_by_ip("192.168.1.10")
        assert router is not None and ep is not None
        assert topo.graph.has_edge(router.node_id, ep.node_id)

    def test_no_merge_different_macs(self):
        """Узлы с разными MAC не должны объединяться."""
        topo = NetworkTopology()
        topo.add_device(Device(ip="1.1.1.1", mac="aa:bb:cc:00:00:01", node_id="a"))
        topo.add_device(Device(ip="1.1.1.2", mac="aa:bb:cc:00:00:02", node_id="b"))
        count = topo.merge_by_mac()
        assert count == 0
        assert len(topo.devices) == 2

    def test_no_merge_empty_mac(self):
        """Узлы без MAC не должны объединяться."""
        topo = NetworkTopology()
        topo.add_device(Device(ip="1.1.1.1", mac=None, node_id="a"))
        topo.add_device(Device(ip="1.1.1.2", mac=None, node_id="b"))
        count = topo.merge_by_mac()
        assert count == 0

    def test_cisco_format_mac(self):
        """MAC в Cisco-формате (aabb.ccdd.eeff) нормализуется корректно."""
        topo = NetworkTopology()
        topo.add_device(Device(ip="10.0.0.1", mac="aabb.ccdd.ee01", node_id="a"))
        topo.add_device(Device(ip="10.0.0.2", mac="AA:BB:CC:DD:EE:01", node_id="b"))
        count = topo.merge_by_mac()
        assert count == 1

    def test_three_way_merge(self):
        """Три узла с одним MAC — все объединяются в один."""
        topo = NetworkTopology()
        mac  = "aa:bb:cc:dd:ee:ff"
        for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
            topo.add_device(Device(ip=ip, mac=mac, node_id=f"n{i}"))
        count = topo.merge_by_mac()
        assert count == 1
        assert len(topo.devices) == 1


# ════════════════════════════════════════════════════════════════════════════
# merge_devices / split_device
# ════════════════════════════════════════════════════════════════════════════

class TestManualMergeSplit:

    def _make_two_node_topo(self):
        topo = NetworkTopology()
        a = Device(ip="192.168.1.1", mac="aa:00:00:00:00:01",
                   device_type="router", node_id="a")
        b = Device(ip="10.0.0.1",    mac="bb:00:00:00:00:01",
                   device_type="server", node_id="b")
        ep = Device(ip="192.168.1.50", node_id="ep")
        for dev in [a, b, ep]:
            topo.add_device(dev)
        topo.add_link("b", "ep", label="ARP")
        return topo, a, b, ep

    def test_merge_devices_success(self):
        topo, a, b, ep = self._make_two_node_topo()
        result = topo.merge_devices("a", "b")
        assert result is True
        assert "b" not in topo.devices
        assert a.is_multihomed is True

    def test_merge_devices_ips_transferred(self):
        topo, a, b, ep = self._make_two_node_topo()
        topo.merge_devices("a", "b")
        assert "10.0.0.1" in a.all_ips()

    def test_merge_devices_edges_transferred(self):
        topo, a, b, ep = self._make_two_node_topo()
        topo.merge_devices("a", "b")
        assert topo.graph.has_edge("a", "ep")

    def test_merge_same_node_returns_false(self):
        topo, a, b, ep = self._make_two_node_topo()
        assert topo.merge_devices("a", "a") is False

    def test_split_device(self):
        topo = NetworkTopology()
        dev = Device(ip="192.168.1.1", subnet="192.168.1.0/24",
                     device_type="router", node_id="r1")
        dev.add_interface("10.0.0.1", subnet="10.0.0.0/24")
        dev.is_multihomed = True
        topo.add_device(dev)

        new_id = topo.split_device("r1", "10.0.0.1")
        assert new_id is not None
        assert new_id in topo.devices
        assert "10.0.0.1" not in dev.all_ips()

    def test_split_only_ip_fails(self):
        topo = NetworkTopology()
        dev  = Device(ip="192.168.1.1", node_id="r1")
        topo.add_device(dev)
        result = topo.split_device("r1", "192.168.1.1")
        assert result is None   # нельзя отделить единственный IP

    def test_split_nonexistent_ip_fails(self):
        topo = NetworkTopology()
        dev  = Device(ip="192.168.1.1", node_id="r1")
        dev.add_interface("10.0.0.1")
        topo.add_device(dev)
        result = topo.split_device("r1", "99.99.99.99")
        assert result is None


# ════════════════════════════════════════════════════════════════════════════
# build_from_multi_subnet
# ════════════════════════════════════════════════════════════════════════════

class TestBuildFromMultiSubnet:

    def test_basic_two_subnets(self):
        topo = NetworkTopology()
        hosts_a = [
            Device(ip="192.168.1.1", mac="aa:00:00:00:00:01",
                   device_type="router", node_id="r1"),
            Device(ip="192.168.1.10", mac="bb:00:00:00:00:01",
                   device_type="endpoint", node_id="ep1"),
        ]
        hosts_b = [
            Device(ip="10.0.0.1", mac="aa:00:00:00:00:01",  # тот же MAC что r1!
                   device_type="unknown", node_id="r2"),
            Device(ip="10.0.0.100", mac="cc:00:00:00:00:01",
                   device_type="server", node_id="srv1"),
        ]
        topo.build_from_multi_subnet([
            ("192.168.1.0/24", hosts_a, None),
            ("10.0.0.0/24",    hosts_b, None),
        ])
        # Дубликат по MAC должен быть объединён
        assert len(topo.devices) == 3  # router(merged) + endpoint + server

    def test_router_becomes_multihomed(self):
        topo = NetworkTopology()
        r1 = Device(ip="192.168.1.1", mac="aa:00:00:00:00:01",
                    device_type="router", node_id="r1")
        r2 = Device(ip="10.0.0.1",    mac="aa:00:00:00:00:01",
                    device_type="router", node_id="r2")
        topo.build_from_multi_subnet([
            ("192.168.1.0/24", [r1], None),
            ("10.0.0.0/24",    [r2], None),
        ])
        router = topo.get_by_ip("192.168.1.1") or topo.get_by_ip("10.0.0.1")
        assert router is not None
        assert router.is_multihomed is True

    def test_no_false_merge_different_macs(self):
        topo = NetworkTopology()
        hosts_a = [Device(ip="192.168.1.1", mac="aa:00:00:00:00:01", node_id="a")]
        hosts_b = [Device(ip="10.0.0.1",    mac="bb:00:00:00:00:02", node_id="b")]
        topo.build_from_multi_subnet([
            ("192.168.1.0/24", hosts_a, None),
            ("10.0.0.0/24",    hosts_b, None),
        ])
        assert len(topo.devices) == 2

    def test_subnets_tagged_on_interfaces(self):
        """После сборки у каждого интерфейса должна быть подсеть."""
        topo   = NetworkTopology()
        hosts  = [Device(ip="192.168.1.1", mac="aa:00:00:00:00:01", node_id="r1")]
        topo.build_from_multi_subnet([("192.168.1.0/24", hosts, None)])
        dev = topo.get_by_ip("192.168.1.1")
        assert dev is not None
        assert any(i.subnet == "192.168.1.0/24" for i in dev.interfaces)

    def test_json_round_trip_multihomed(self, tmp_path):
        """Мультиинтерфейсный узел сохраняется и загружается корректно."""
        topo = NetworkTopology()
        r1 = Device(ip="192.168.1.1", mac="aa:00:00:00:00:01",
                    device_type="router", node_id="r1")
        r2 = Device(ip="10.0.0.1",    mac="aa:00:00:00:00:01",
                    device_type="router", node_id="r2")
        topo.build_from_multi_subnet([
            ("192.168.1.0/24", [r1], None),
            ("10.0.0.0/24",    [r2], None),
        ])
        path = str(tmp_path / "multi.json")
        topo.save_json(path)

        topo2 = NetworkTopology()
        topo2.load_json(path)
        multi = [d for d in topo2.devices.values() if d.is_multihomed]
        assert len(multi) == 1
        assert len(multi[0].all_ips()) >= 2


# ════════════════════════════════════════════════════════════════════════════
# parse_snmp_services
# ════════════════════════════════════════════════════════════════════════════

class TestParseSNMPServices:
    def test_router_mask_4(self):
        assert parse_snmp_services("4") == "router"

    def test_switch_mask_2(self):
        assert parse_snmp_services("2") == "switch"

    def test_server_mask_64(self):
        assert parse_snmp_services("64") == "server"

    def test_none_on_zero(self):
        assert parse_snmp_services("0") is None

    def test_none_on_invalid(self):
        assert parse_snmp_services("abc") is None


# ════════════════════════════════════════════════════════════════════════════
# classify_by_ports
# ════════════════════════════════════════════════════════════════════════════

class TestClassifyByPorts:
    def test_web_server(self):
        assert classify_by_ports([80, 443]) == "server"

    def test_mail_server(self):
        assert classify_by_ports([22, 25, 443]) == "server"

    def test_empty_ports(self):
        assert classify_by_ports([]) is None

    def test_rdp(self):
        assert classify_by_ports([3389]) in ("endpoint", "server")

    def test_database(self):
        assert classify_by_ports([3306]) == "server"


# ════════════════════════════════════════════════════════════════════════════
# CLI-таблица: мультиинтерфейсные помечены *
# ════════════════════════════════════════════════════════════════════════════

class TestCLITable:
    def test_star_in_output(self, capsys):
        from net_topology import print_cli_table
        topo = NetworkTopology()
        dev  = Device(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF",
                      device_type="router", node_id="r1")
        dev.add_interface("10.0.0.1", subnet="10.0.0.0/24")
        dev.is_multihomed = True
        topo.add_device(dev)
        print_cli_table(topo)
        captured = capsys.readouterr()
        assert "*" in captured.out

    def test_no_star_for_single(self, capsys):
        from net_topology import print_cli_table
        topo = NetworkTopology()
        dev  = Device(ip="192.168.1.10", device_type="endpoint", node_id="ep1")
        topo.add_device(dev)
        print_cli_table(topo)
        captured = capsys.readouterr()
        # Строка с этим IP не должна начинаться с *
        for line in captured.out.splitlines():
            if "192.168.1.10" in line:
                assert not line.strip().startswith("*")
