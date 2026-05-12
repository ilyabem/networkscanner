"""
model.py — модель данных топологии сети.

Содержит классы Device и NetworkTopology.
NetworkTopology является центральным хранилищем состояния:
граф NetworkX + словарь устройств + список связей.

ДОРАБОТКА (multi-subnet / multi-homed):
  - Новый датакласс Interface: хранит один IP + подсеть + имя интерфейса.
  - Device.interfaces — список всех интерфейсов устройства.
  - Device.is_multihomed — флаг мультиинтерфейсности.
  - normalize_mac() — нормализация MAC в единый формат AA:BB:CC:DD:EE:FF.
  - NetworkTopology.build_from_multi_subnet() — сборка топологии из нескольких подсетей.
  - NetworkTopology.merge_by_mac() — объединение узлов по совпадающему MAC.
  - NetworkTopology.merge_devices() — ручное объединение двух узлов из GUI.
  - NetworkTopology.split_device() — ручное разделение мультиинтерфейсного узла.
  - Экспорт JSON/GraphML сохраняет признак мультиинтерфейсности и все IP.
"""

from __future__ import annotations

import json
import logging
import math
import re
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

import networkx as nx

logger = logging.getLogger("model")

# ─── Допустимые типы устройств ──────────────────────────────────────────────
DEVICE_TYPES = [
    "router",
    "switch",
    "bridge",
    "firewall",
    "server",
    "endpoint",
    "unknown",
]

TYPE_COLORS: dict[str, str] = {
    "router":   "#e74c3c",
    "switch":   "#2980b9",
    "bridge":   "#8e44ad",
    "firewall": "#e67e22",
    "server":   "#27ae60",
    "endpoint": "#95a5a6",
    "unknown":  "#bdc3c7",
}

TYPE_SHAPES: dict[str, str] = {
    "router":   "diamond",
    "switch":   "square",
    "bridge":   "hexagon",
    "firewall": "triangle",
    "server":   "circle",
    "endpoint": "circle",
    "unknown":  "circle",
}


# ─── Нормализация MAC-адреса ─────────────────────────────────────────────────

def normalize_mac(mac: str) -> str:
    """
    Приводит MAC-адрес к единому формату AA:BB:CC:DD:EE:FF (верхний регистр).

    Поддерживаемые форматы входа:
      aa:bb:cc:dd:ee:ff   — Linux
      AA-BB-CC-DD-EE-FF   — Windows
      aabb.ccdd.eeff      — Cisco
      aabbccddeeff        — без разделителей

    Возвращает пустую строку, если формат не распознан.
    """
    if not mac:
        return ""
    clean = re.sub(r"[:\-\.]", "", mac).upper()
    if len(clean) != 12 or not re.fullmatch(r"[0-9A-F]{12}", clean):
        return ""
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))


# ─── Один сетевой интерфейс ──────────────────────────────────────────────────

@dataclass
class Interface:
    """
    Один сетевой интерфейс устройства.
    Хранит IP-адрес, подсеть CIDR и имя порта (если известно).
    """
    ip: str
    subnet: str = ""        # CIDR подсети, в которой найден IP
    iface_name: str = ""    # имя интерфейса: eth0, GigabitEthernet0/0 и т.п.

    def to_dict(self) -> dict[str, str]:
        return {"ip": self.ip, "subnet": self.subnet, "iface_name": self.iface_name}

    @classmethod
    def from_dict(cls, d: dict) -> "Interface":
        return cls(
            ip=d.get("ip", ""),
            subnet=d.get("subnet", ""),
            iface_name=d.get("iface_name", ""),
        )


# ─── Устройство ──────────────────────────────────────────────────────────────

@dataclass
class Device:
    """
    Описание одного сетевого устройства.

    ДОРАБОТКА — новые поля:
      subnet        — CIDR подсети, в которой устройство обнаружено впервые.
      interfaces    — список всех известных интерфейсов (IP + подсеть + имя).
      is_multihomed — True, если устройство имеет интерфейсы в нескольких подсетях.

    Поле `ip` хранит «основной» IP (первый обнаруженный).
    Все остальные IP доступны через device.all_ips() / device.interfaces.
    """

    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str = "unknown"
    open_ports: list[int] = field(default_factory=list)
    ttl: int | None = None
    snmp_info: dict[str, str] = field(default_factory=dict)
    node_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    position: tuple[float, float] | None = None
    notes: str = ""

    # ── Новые поля для multi-subnet ──────────────────────────────────────────
    subnet: str = ""
    interfaces: list[Interface] = field(default_factory=list)
    is_multihomed: bool = False

    def __post_init__(self) -> None:
        """Автоматически добавляем основной IP в список интерфейсов."""
        if self.ip and not any(iface.ip == self.ip for iface in self.interfaces):
            self.interfaces.append(Interface(ip=self.ip, subnet=self.subnet))

    # ── Работа с интерфейсами ────────────────────────────────────────────────

    def add_interface(self, ip: str, subnet: str = "", iface_name: str = "") -> None:
        """Добавить интерфейс, если такого IP ещё нет."""
        if not any(iface.ip == ip for iface in self.interfaces):
            self.interfaces.append(Interface(ip=ip, subnet=subnet, iface_name=iface_name))
            logger.debug("Устройство %s: добавлен интерфейс %s (%s)", self.ip, ip, subnet)

    def all_ips(self) -> list[str]:
        """Список всех IP-адресов устройства."""
        return [iface.ip for iface in self.interfaces]

    def interfaces_label(self) -> str:
        """Многострочная подпись с перечислением всех интерфейсов."""
        lines = []
        for iface in self.interfaces:
            name_part   = f" ({iface.iface_name})" if iface.iface_name else ""
            subnet_part = f" [{iface.subnet}]"     if iface.subnet     else ""
            lines.append(f"{iface.ip}{name_part}{subnet_part}")
        return "\n".join(lines)

    def label(self) -> str:
        """Метка узла для отображения в GUI."""
        name = self.hostname or self.ip
        if self.is_multihomed:
            # ★ — визуальный маркер мультиинтерфейсного устройства
            return f"★ {name}\n[{self.device_type}]\n{self.interfaces_label()}"
        return f"{name}\n[{self.device_type}]"

    # ── Сериализация ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # interfaces: список dataclass → список dict
        d["interfaces"] = [iface.to_dict() for iface in self.interfaces]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Device":
        if data.get("position") and not isinstance(data["position"], tuple):
            data["position"] = tuple(data["position"])
        # Извлекаем interfaces отдельно, чтобы не передать их в __init__ как dict
        raw_ifaces = data.pop("interfaces", [])
        obj = cls(**data)
        obj.interfaces = [Interface.from_dict(i) for i in raw_ifaces]
        # Убеждаемся, что основной IP есть в списке
        if obj.ip and not any(iface.ip == obj.ip for iface in obj.interfaces):
            obj.interfaces.insert(0, Interface(ip=obj.ip, subnet=obj.subnet))
        return obj


# ─── Связь ───────────────────────────────────────────────────────────────────

@dataclass
class Link:
    """Связь между двумя устройствами в графе."""
    src_id: str
    dst_id: str
    label: str = ""
    bandwidth: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Link":
        return cls(**data)


# ─── Топология ───────────────────────────────────────────────────────────────

class NetworkTopology:
    """
    Центральное хранилище топологии сети.

    Граф NetworkX (неориентированный) + словарь устройств.
    Узлы графа идентифицируются по node_id; все атрибуты — в словаре devices.

    ДОРАБОТКА:
      build_from_multi_subnet() — принимает результаты нескольких сканирований,
          автоматически вызывает merge_by_mac() и строит межсетевые связи.
      merge_by_mac()    — находит дубли по MAC, объединяет узлы.
      merge_devices()   — ручное объединение двух узлов (из GUI).
      split_device()    — ручное разделение мультиинтерфейсного узла (из GUI).
    """

    def __init__(self) -> None:
        self.graph: nx.Graph = nx.Graph()
        self.devices: dict[str, Device] = {}
        self._ip_to_id: dict[str, str] = {}   # ip → node_id

    # ── Добавление / удаление ────────────────────────────────────────────────

    def add_device(self, device: Device) -> str:
        """Добавить устройство. Возвращает node_id."""
        nid = device.node_id
        self.devices[nid] = device
        # Регистрируем все IP в индексе
        self._ip_to_id[device.ip] = nid
        for iface in device.interfaces:
            self._ip_to_id[iface.ip] = nid
        self.graph.add_node(nid)
        logger.debug("Добавлено %s (%s)", device.ip, device.device_type)
        return nid

    def remove_device(self, node_id: str) -> None:
        """Удалить устройство и все его связи."""
        if node_id not in self.devices:
            return
        dev = self.devices.pop(node_id)
        self._ip_to_id.pop(dev.ip, None)
        for iface in dev.interfaces:
            self._ip_to_id.pop(iface.ip, None)
        self.graph.remove_node(node_id)
        logger.debug("Удалено %s", dev.ip)

    def get_by_ip(self, ip: str) -> Device | None:
        nid = self._ip_to_id.get(ip)
        return self.devices.get(nid) if nid else None

    # ── Связи ────────────────────────────────────────────────────────────────

    def add_link(self, src_id: str, dst_id: str, label: str = "") -> None:
        if src_id == dst_id:
            return
        if not self.graph.has_edge(src_id, dst_id):
            self.graph.add_edge(src_id, dst_id, label=label)
            logger.debug("Связь %s — %s [%s]", src_id, dst_id, label)

    def remove_link(self, src_id: str, dst_id: str) -> None:
        if self.graph.has_edge(src_id, dst_id):
            self.graph.remove_edge(src_id, dst_id)

    @property
    def links(self) -> list[tuple[str, str, dict]]:
        return list(self.graph.edges(data=True))

    # ── Одна подсеть (обратная совместимость) ────────────────────────────────

    def build_from_hosts(
        self,
        hosts: list[Device],
        arp_table: dict[str, list[tuple[str, str]]] | None = None,
        subnet: str = "",
    ) -> None:
        """
        Строит граф из одной подсети.
        Полностью совместим с предыдущей версией — subnet опционален.
        """
        for host in hosts:
            if subnet and not host.subnet:
                host.subnet = subnet
                if host.interfaces:
                    host.interfaces[0].subnet = subnet
        self._add_hosts_and_links(hosts, arp_table)
        self._assign_positions()

    # ── Несколько подсетей ───────────────────────────────────────────────────

    def build_from_multi_subnet(
        self,
        subnet_results: list[
            tuple[str, list[Device], dict[str, list[tuple[str, str]]] | None]
        ],
    ) -> None:
        """
        Строит топологию из нескольких подсетей.

        Аргумент subnet_results — список кортежей вида:
            (subnet_cidr, hosts_list, arp_table_or_None)

        Алгоритм:
          1. Добавляем хосты из каждой подсети, проставляя subnet в интерфейсы.
          2. Строим связи по ARP-таблице каждой подсети.
          3. Объединяем узлы с одинаковым MAC (merge_by_mac) — убираем дубли.
          4. Добавляем межсетевые связи через мультиинтерфейсные шлюзы.
          5. Назначаем позиции узлам.
        """
        for subnet, hosts, arp_table in subnet_results:
            logger.info("Обрабатываем подсеть %s (%d хостов)", subnet, len(hosts))
            for host in hosts:
                if not host.subnet:
                    host.subnet = subnet
                for iface in host.interfaces:
                    if not iface.subnet:
                        iface.subnet = subnet
            self._add_hosts_and_links(hosts, arp_table)

        # Ключевой шаг: объединяем узлы с одинаковым MAC
        merged = self.merge_by_mac()
        logger.info("Объединено по MAC: %d узлов", merged)

        # Добавляем связи через межсетевые шлюзы
        self._add_intersubnet_links()

        self._assign_positions()

    # ── Объединение по MAC ───────────────────────────────────────────────────

    def merge_by_mac(self) -> int:
        """
        Находит устройства с одинаковым нормализованным MAC и объединяет их.

        Возвращает количество произведённых объединений (групп дублей).

        Шаги:
          1. Группируем node_id по нормализованному MAC.
          2. В группах с >1 узлом выбираем «главный» (по типу и степени узла).
          3. Переносим интерфейсы дублей в главный узел.
          4. Перекидываем все рёбра дублей на главный узел.
          5. Удаляем дубли; главный помечается is_multihomed=True.
        """
        # Шаг 1: группировка
        mac_groups: dict[str, list[str]] = {}
        for nid, dev in self.devices.items():
            if not dev.mac:
                continue
            norm = normalize_mac(dev.mac)
            if norm:
                mac_groups.setdefault(norm, []).append(nid)

        merged_count = 0
        for norm_mac, nids in mac_groups.items():
            if len(nids) < 2:
                continue

            ips = [self.devices[n].ip for n in nids]
            logger.info("Дубль MAC %s у узлов %s — объединяем", norm_mac, ips)

            # Шаг 2: выбор главного
            primary_id = self._choose_primary(nids)
            primary    = self.devices[primary_id]

            for nid in nids:
                if nid == primary_id:
                    continue
                dup = self.devices[nid]

                # Шаг 3: перенос интерфейсов
                for iface in dup.interfaces:
                    primary.add_interface(iface.ip, iface.subnet, iface.iface_name)

                # Шаг 4: перенос рёбер
                for neighbor in list(self.graph.neighbors(nid)):
                    if neighbor != primary_id:
                        edge_attrs = self.graph.edges[nid, neighbor]
                        self.add_link(primary_id, neighbor, edge_attrs.get("label", ""))

                # Обновляем индекс ip→id
                for iface in dup.interfaces:
                    self._ip_to_id[iface.ip] = primary_id
                self._ip_to_id.pop(dup.ip, None)

                # Удаляем дубль
                self.graph.remove_node(nid)
                self.devices.pop(nid)
                logger.debug("Узел %s (%s) удалён как дубль → %s", nid, dup.ip, primary_id)

            # Шаг 5: помечаем главный
            primary.is_multihomed = True
            primary.mac = norm_mac
            merged_count += 1

        return merged_count

    def _choose_primary(self, nids: list[str]) -> str:
        """
        Выбирает главный узел при слиянии.
        Приоритет типов: router > firewall > switch > bridge > server > endpoint > unknown.
        Тиобрейкер — степень узла в графе (больше связей = центральнее).
        """
        priority = {
            "router": 7, "firewall": 6, "switch": 5,
            "bridge": 4, "server": 3, "endpoint": 2, "unknown": 1,
        }
        return max(
            nids,
            key=lambda n: (
                priority.get(self.devices[n].device_type, 0),
                self.graph.degree(n),
            ),
        )

    # ── Межсетевые связи ─────────────────────────────────────────────────────

    def _add_intersubnet_links(self) -> None:
        """
        Для каждого мультиинтерфейсного устройства (шлюза):
          - Собираем подсети его интерфейсов.
          - Соединяем шлюз с каждым устройством в тех же подсетях.

        Это отражает реальную топологию: шлюз связывает разные сегменты сети.
        """
        for nid, dev in list(self.devices.items()):
            if not dev.is_multihomed:
                continue
            gw_subnets = {iface.subnet for iface in dev.interfaces if iface.subnet}
            for other_id, other_dev in self.devices.items():
                if other_id == nid:
                    continue
                other_subnets = {iface.subnet for iface in other_dev.interfaces if iface.subnet}
                if gw_subnets & other_subnets:  # есть общая подсеть
                    self.add_link(nid, other_id, label="inter-subnet")

    # ── Ручное объединение (из GUI) ───────────────────────────────────────────

    def merge_devices(self, primary_id: str, secondary_id: str) -> bool:
        """
        Ручное объединение двух узлов: secondary поглощается primary.
        Вызывается из GUI, когда пользователь хочет скорректировать автоматику.
        Возвращает True при успехе.
        """
        if primary_id not in self.devices or secondary_id not in self.devices:
            logger.warning("merge_devices: узел не найден (%s / %s)", primary_id, secondary_id)
            return False
        if primary_id == secondary_id:
            return False

        primary   = self.devices[primary_id]
        secondary = self.devices[secondary_id]
        logger.info("Ручное объединение: %s ← %s", primary.ip, secondary.ip)

        for iface in secondary.interfaces:
            primary.add_interface(iface.ip, iface.subnet, iface.iface_name)

        for neighbor in list(self.graph.neighbors(secondary_id)):
            if neighbor != primary_id:
                attrs = self.graph.edges[secondary_id, neighbor]
                self.add_link(primary_id, neighbor, attrs.get("label", "manual-merge"))

        for iface in secondary.interfaces:
            self._ip_to_id[iface.ip] = primary_id
        self._ip_to_id.pop(secondary.ip, None)

        self.graph.remove_node(secondary_id)
        self.devices.pop(secondary_id)
        primary.is_multihomed = True
        return True

    # ── Ручное разделение (из GUI) ────────────────────────────────────────────

    def split_device(self, node_id: str, split_ip: str) -> str | None:
        """
        Отделяет интерфейс с указанным IP в новый самостоятельный узел.
        Используется из GUI для исправления ошибочного объединения.
        Возвращает node_id нового узла или None при ошибке.
        """
        if node_id not in self.devices:
            return None

        primary = self.devices[node_id]
        iface_to_split = next(
            (i for i in primary.interfaces if i.ip == split_ip), None
        )
        if not iface_to_split:
            logger.warning("split_device: IP %s не найден в %s", split_ip, node_id)
            return None
        if split_ip == primary.ip and len(primary.interfaces) <= 1:
            logger.warning("split_device: нельзя отделить единственный интерфейс")
            return None

        new_dev = Device(
            ip=split_ip,
            mac=None,
            subnet=iface_to_split.subnet,
            device_type=primary.device_type,
            notes=f"Отделён от {primary.ip}",
        )
        self.add_device(new_dev)

        # Убираем отщеплённый IP из основного узла
        primary.interfaces = [i for i in primary.interfaces if i.ip != split_ip]
        self._ip_to_id.pop(split_ip, None)

        # Пересчитываем флаг мультиинтерфейсности
        subnets = {i.subnet for i in primary.interfaces if i.subnet}
        primary.is_multihomed = len(subnets) > 1

        logger.info("Разделение: %s → новый узел %s (%s)", node_id, new_dev.node_id, split_ip)
        return new_dev.node_id

    # ── Внутренние методы ────────────────────────────────────────────────────

    def _add_hosts_and_links(
        self,
        hosts: list[Device],
        arp_table: dict[str, list[tuple[str, str]]] | None,
    ) -> None:
        """
        Добавляет хосты в граф (без дублирования по IP) и строит связи.
        Если хост с таким IP уже есть — добавляем только новые интерфейсы.
        """
        for host in hosts:
            existing = self.get_by_ip(host.ip)
            if existing:
                for iface in host.interfaces:
                    existing.add_interface(iface.ip, iface.subnet, iface.iface_name)
            else:
                self.add_device(host)

        if arp_table:
            for gw_ip, entries in arp_table.items():
                gw_dev = self.get_by_ip(gw_ip)
                if not gw_dev:
                    continue
                for ip, _mac in entries:
                    peer = self.get_by_ip(ip)
                    if peer:
                        self.add_link(gw_dev.node_id, peer.node_id, label="ARP")
        else:
            hub = self._find_hub()
            if hub:
                for nid in list(self.devices):
                    if nid != hub.node_id:
                        self.add_link(hub.node_id, nid, label="heuristic")

    def _find_hub(self) -> Device | None:
        """Находит наиболее вероятный центральный узел для эвристических связей."""
        for ptype in ["router", "firewall", "switch", "bridge"]:
            for dev in self.devices.values():
                if dev.device_type == ptype:
                    return dev
        return next(iter(self.devices.values()), None)

    def _assign_positions(self) -> None:
        """
        Назначает координаты узлам на canvas.
        Использует spring_layout (numpy) или круговое расположение как fallback.
        """
        if not self.graph.nodes:
            return
        try:
            pos = nx.spring_layout(self.graph, seed=42, k=2.0)
        except Exception:
            nodes = list(self.graph.nodes)
            n = len(nodes)
            pos = {
                nid: (math.cos(2 * math.pi * i / max(n, 1)),
                      math.sin(2 * math.pi * i / max(n, 1)))
                for i, nid in enumerate(nodes)
            }
        for nid, (x, y) in pos.items():
            if nid in self.devices:
                self.devices[nid].position = (
                    (x + 1) / 2 * 700 + 50,
                    (y + 1) / 2 * 500 + 50,
                )

    # ── Сериализация ─────────────────────────────────────────────────────────

    def save_json(self, path: str) -> None:
        """Сохранить топологию в JSON с поддержкой multi-homed."""
        data = {
            "devices": {nid: dev.to_dict() for nid, dev in self.devices.items()},
            "links": [
                {"src": src, "dst": dst, "label": attrs.get("label", "")}
                for src, dst, attrs in self.links
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("Сохранено в %s", path)

    def load_json(self, path: str) -> None:
        """Загрузить топологию из JSON."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.graph.clear()
        self.devices.clear()
        self._ip_to_id.clear()
        for nid, dev_data in data.get("devices", {}).items():
            dev = Device.from_dict(dev_data)
            dev.node_id = nid
            self.add_device(dev)
        for link in data.get("links", []):
            self.add_link(link["src"], link["dst"], link.get("label", ""))
        logger.info("Загружено из %s (%d устройств)", path, len(self.devices))

    def export_graphml(self, path: str) -> None:
        """Экспортировать граф в GraphML с атрибутами multi-homed."""
        for nid, dev in self.devices.items():
            self.graph.nodes[nid]["ip"]         = dev.ip
            self.graph.nodes[nid]["all_ips"]    = ",".join(dev.all_ips())
            self.graph.nodes[nid]["type"]       = dev.device_type
            self.graph.nodes[nid]["label"]      = dev.hostname or dev.ip
            self.graph.nodes[nid]["multihomed"] = str(dev.is_multihomed)
            self.graph.nodes[nid]["subnets"]    = ",".join(
                {i.subnet for i in dev.interfaces if i.subnet}
            )
        nx.write_graphml(self.graph, path)
        logger.info("Экспортировано в GraphML: %s", path)
