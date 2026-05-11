"""
tests/test_topology.py — юнит-тесты для ключевых компонентов.

Запуск:
    pip install pytest
    pytest tests/ -v

Тесты НЕ требуют наличия сети, nmap или scapy.
Они тестируют только чистые функции анализа и модели.
"""

import sys
import os

# Добавляем корень проекта в sys.path, чтобы импортировать модули
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from model import Device, NetworkTopology, DEVICE_TYPES
from analyzer import classify_by_ports, parse_snmp_services, DeviceAnalyzer


# ════════════════════════════════════════════════════════════════════════════
# Тесты: parse_snmp_services (парсинг sysServices)
# ════════════════════════════════════════════════════════════════════════════

class TestParseSNMPServices:
    """Тесты парсинга битовой маски sysServices из SNMP."""

    def test_router_mask_4(self):
        """sysServices=4 (L3 routing) → router"""
        assert parse_snmp_services("4") == "router"

    def test_router_mask_6(self):
        """sysServices=6 (L2+L3) → router (L3 бит перевешивает)"""
        assert parse_snmp_services("6") == "router"

    def test_switch_mask_2(self):
        """sysServices=2 (только L2) → switch"""
        assert parse_snmp_services("2") == "switch"

    def test_server_mask_64(self):
        """sysServices=64 (приложения, L7) → server"""
        assert parse_snmp_services("64") == "server"

    def test_server_mask_78(self):
        """sysServices=78 (L1+L2+L3+L7) → server (приложения важнее)"""
        assert parse_snmp_services("78") == "server"

    def test_none_on_zero(self):
        """sysServices=0 → None (тип не определён)"""
        assert parse_snmp_services("0") is None

    def test_none_on_invalid(self):
        """Некорректная строка → None"""
        assert parse_snmp_services("abc") is None

    def test_none_on_empty(self):
        """Пустая строка → None"""
        assert parse_snmp_services("") is None


# ════════════════════════════════════════════════════════════════════════════
# Тесты: classify_by_ports (определение типа по открытым портам)
# ════════════════════════════════════════════════════════════════════════════

class TestClassifyByPorts:
    """Тесты классификации устройства по открытым портам."""

    def test_web_server(self):
        """Порты 80 и 443 → server"""
        result = classify_by_ports([80, 443])
        assert result == "server"

    def test_mail_server(self):
        """Порт 25 (SMTP) — сервер с дефинитивным набором"""
        result = classify_by_ports([22, 25, 443])
        assert result == "server"

    def test_snmp_router(self):
        """SNMP (161) + Telnet (23) → router или switch"""
        result = classify_by_ports([23, 161])
        assert result in ("router", "switch")

    def test_rdp_endpoint(self):
        """RDP (3389) без других портов → endpoint или server"""
        result = classify_by_ports([3389])
        assert result in ("endpoint", "server")

    def test_empty_ports(self):
        """Нет открытых портов → None"""
        assert classify_by_ports([]) is None

    def test_unknown_ports(self):
        """Неизвестные порты → None"""
        assert classify_by_ports([12345, 54321]) is None

    def test_ssh_only(self):
        """SSH (22) → server или router"""
        result = classify_by_ports([22])
        assert result in ("server", "router")

    def test_database_server(self):
        """MySQL (3306) → server (дефинитивный порт)"""
        result = classify_by_ports([3306])
        assert result == "server"

    def test_mixed_signals(self):
        """Несколько портов с разными подсказками — результат не None"""
        result = classify_by_ports([22, 80, 161, 443])
        assert result is not None
        assert result in DEVICE_TYPES


# ════════════════════════════════════════════════════════════════════════════
# Тесты: NetworkTopology (модель данных и граф)
# ════════════════════════════════════════════════════════════════════════════

class TestNetworkTopology:
    """Тесты модели топологии сети."""

    def _make_topology(self) -> tuple[NetworkTopology, list[Device]]:
        """Вспомогательный метод: создаёт топологию с несколькими устройствами."""
        topo = NetworkTopology()
        router  = Device(ip="192.168.1.1", device_type="router",   node_id="r1")
        switch  = Device(ip="192.168.1.2", device_type="switch",   node_id="sw1")
        server  = Device(ip="192.168.1.10", device_type="server",  node_id="srv1")
        endpoint = Device(ip="192.168.1.20", device_type="endpoint", node_id="ep1")
        for dev in [router, switch, server, endpoint]:
            topo.add_device(dev)
        return topo, [router, switch, server, endpoint]

    def test_add_devices(self):
        topo, devs = self._make_topology()
        assert len(topo.devices) == 4
        assert len(topo.graph.nodes) == 4

    def test_get_by_ip(self):
        topo, _ = self._make_topology()
        dev = topo.get_by_ip("192.168.1.1")
        assert dev is not None
        assert dev.device_type == "router"

    def test_get_by_ip_missing(self):
        topo, _ = self._make_topology()
        assert topo.get_by_ip("10.0.0.1") is None

    def test_add_link(self):
        topo, devs = self._make_topology()
        router, switch = devs[0], devs[1]
        topo.add_link(router.node_id, switch.node_id, label="ARP")
        assert topo.graph.has_edge(router.node_id, switch.node_id)
        assert len(topo.links) == 1

    def test_add_duplicate_link(self):
        """Дублирующиеся связи не добавляются."""
        topo, devs = self._make_topology()
        r, s = devs[0].node_id, devs[1].node_id
        topo.add_link(r, s)
        topo.add_link(r, s)  # повторно
        assert len(topo.links) == 1

    def test_add_self_link(self):
        """Петли (узел → себя) не добавляются."""
        topo, devs = self._make_topology()
        nid = devs[0].node_id
        topo.add_link(nid, nid)
        assert len(topo.links) == 0

    def test_remove_link(self):
        topo, devs = self._make_topology()
        r, s = devs[0].node_id, devs[1].node_id
        topo.add_link(r, s)
        topo.remove_link(r, s)
        assert not topo.graph.has_edge(r, s)

    def test_remove_device(self):
        topo, devs = self._make_topology()
        r, s = devs[0], devs[1]
        topo.add_link(r.node_id, s.node_id)
        topo.remove_device(r.node_id)
        assert r.node_id not in topo.devices
        assert not topo.graph.has_node(r.node_id)
        # Связь тоже должна исчезнуть
        assert not topo.graph.has_edge(r.node_id, s.node_id)

    def test_build_from_hosts_no_arp(self):
        """build_from_hosts без ARP-таблицы: эвристика — все к хабу."""
        topo = NetworkTopology()
        hosts = [
            Device(ip="192.168.1.1", device_type="router",   node_id="r1"),
            Device(ip="192.168.1.2", device_type="endpoint", node_id="ep1"),
            Device(ip="192.168.1.3", device_type="endpoint", node_id="ep2"),
        ]
        topo.build_from_hosts(hosts, arp_table=None)
        # Должна быть хотя бы одна связь (от роутера к endpoints)
        assert len(topo.links) >= 1

    def test_build_from_hosts_with_arp(self):
        """build_from_hosts с ARP-таблицей: связи по ARP."""
        topo = NetworkTopology()
        hosts = [
            Device(ip="192.168.1.1", device_type="router",   node_id="r1"),
            Device(ip="192.168.1.2", device_type="endpoint", node_id="ep1"),
        ]
        arp = {"192.168.1.1": [("192.168.1.2", "aa:bb:cc:dd:ee:ff")]}
        topo.build_from_hosts(hosts, arp_table=arp)
        assert topo.graph.has_edge("r1", "ep1")

    def test_save_and_load_json(self, tmp_path):
        """Сохранение и загрузка JSON — данные должны совпадать."""
        topo, devs = self._make_topology()
        topo.add_link(devs[0].node_id, devs[1].node_id, label="test")

        path = str(tmp_path / "topology.json")
        topo.save_json(path)

        topo2 = NetworkTopology()
        topo2.load_json(path)

        assert len(topo2.devices) == len(topo.devices)
        assert len(topo2.links) == len(topo.links)
        assert topo2.get_by_ip("192.168.1.1") is not None

    def test_export_graphml(self, tmp_path):
        """Экспорт GraphML не должен вызывать исключений."""
        topo, devs = self._make_topology()
        topo.add_link(devs[0].node_id, devs[1].node_id)
        path = str(tmp_path / "topology.graphml")
        topo.export_graphml(path)
        assert os.path.exists(path)

    def test_positions_assigned(self):
        """После build_from_hosts у каждого устройства должна быть позиция."""
        topo = NetworkTopology()
        hosts = [
            Device(ip="10.0.0.1", device_type="router",   node_id="r1"),
            Device(ip="10.0.0.2", device_type="endpoint", node_id="ep1"),
        ]
        topo.build_from_hosts(hosts)
        for dev in topo.devices.values():
            assert dev.position is not None, f"Позиция не назначена для {dev.ip}"


# ════════════════════════════════════════════════════════════════════════════
# Тесты: DeviceAnalyzer._classify_by_keywords
# ════════════════════════════════════════════════════════════════════════════

class TestClassifyByKeywords:
    """Тесты классификации по ключевым словам."""

    def test_cisco_ios(self):
        result = DeviceAnalyzer._classify_by_keywords("Cisco IOS Software, Version 15.2")
        assert result == "router"

    def test_mikrotik(self):
        result = DeviceAnalyzer._classify_by_keywords("MikroTik RouterOS 6.49")
        assert result == "router"

    def test_linux_server(self):
        result = DeviceAnalyzer._classify_by_keywords("Linux ubuntu 5.15.0-generic #18-Ubuntu")
        assert result == "server"

    def test_pfsense(self):
        result = DeviceAnalyzer._classify_by_keywords("pfSense 2.7.0-RELEASE")
        assert result == "firewall"

    def test_hp_switch(self):
        result = DeviceAnalyzer._classify_by_keywords("HP ProCurve Switch 2810-24G")
        assert result == "switch"

    def test_windows_endpoint(self):
        result = DeviceAnalyzer._classify_by_keywords("Windows 10 Pro")
        assert result == "endpoint"

    def test_unknown_text(self):
        result = DeviceAnalyzer._classify_by_keywords("XYZ Device 12345 unknown vendor")
        assert result is None


# ════════════════════════════════════════════════════════════════════════════
# Тесты: Device сериализация
# ════════════════════════════════════════════════════════════════════════════

class TestDeviceSerialization:
    def test_round_trip(self):
        """to_dict → from_dict должна восстанавливать устройство."""
        dev = Device(
            ip="10.0.0.5",
            mac="AA:BB:CC:DD:EE:FF",
            hostname="myserver.local",
            device_type="server",
            open_ports=[22, 80, 443],
            position=(100.0, 200.0),
            notes="тест",
        )
        restored = Device.from_dict(dev.to_dict())
        assert restored.ip == dev.ip
        assert restored.mac == dev.mac
        assert restored.hostname == dev.hostname
        assert restored.device_type == dev.device_type
        assert restored.open_ports == dev.open_ports
        assert restored.position == dev.position
        assert restored.notes == dev.notes

    def test_label(self):
        dev = Device(ip="1.2.3.4", hostname="myhost", device_type="router")
        assert "myhost" in dev.label()
        assert "router" in dev.label()

    def test_label_no_hostname(self):
        dev = Device(ip="1.2.3.4", device_type="switch")
        assert "1.2.3.4" in dev.label()
