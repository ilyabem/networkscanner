"""
model.py — модель данных топологии сети.

Содержит классы Device и NetworkTopology.
NetworkTopology является центральным хранилищем состояния:
граф NetworkX + словарь устройств + список связей.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

import networkx as nx

logger = logging.getLogger("model")

# ─── Допустимые типы устройств ──────────────────────────────────────────────
DEVICE_TYPES = [
    "router",      # маршрутизатор
    "switch",      # коммутатор
    "bridge",      # бридж
    "firewall",    # межсетевой экран
    "server",      # сервер
    "endpoint",    # конечная точка (ПК, принтер и т.п.)
    "unknown",     # тип не определён
]

# Цвета узлов по типу для GUI (QColor-совместимые строки)
TYPE_COLORS: dict[str, str] = {
    "router":   "#e74c3c",   # красный
    "switch":   "#2980b9",   # синий
    "bridge":   "#8e44ad",   # фиолетовый
    "firewall": "#e67e22",   # оранжевый
    "server":   "#27ae60",   # зелёный
    "endpoint": "#95a5a6",   # серый
    "unknown":  "#bdc3c7",   # светло-серый
}

# Формы узлов (используется в GUI для рисования)
TYPE_SHAPES: dict[str, str] = {
    "router":   "diamond",
    "switch":   "square",
    "bridge":   "hexagon",
    "firewall": "triangle",
    "server":   "circle",
    "endpoint": "circle",
    "unknown":  "circle",
}


@dataclass
class Device:
    """Описание одного сетевого устройства."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str = "unknown"
    # Открытые порты, найденные при сканировании
    open_ports: list[int] = field(default_factory=list)
    # TTL из ICMP-ответа (подсказка для определения ОС)
    ttl: int | None = None
    # Сырые данные SNMP (sysDescr, sysServices и т.п.)
    snmp_info: dict[str, str] = field(default_factory=dict)
    # Уникальный идентификатор узла в графе (генерируется при создании)
    node_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    # Позиция узла на canvas (x, y) — заполняется GUI или при загрузке
    position: tuple[float, float] | None = None
    # Произвольные пользовательские пометки
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Сериализация в словарь для JSON-экспорта."""
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Device":
        """Десериализация из словаря."""
        # position хранится как список в JSON — преобразуем в tuple
        if data.get("position") and not isinstance(data["position"], tuple):
            data["position"] = tuple(data["position"])
        return cls(**data)

    def label(self) -> str:
        """Метка для отображения на схеме."""
        name = self.hostname or self.ip
        return f"{name}\n[{self.device_type}]"


@dataclass
class Link:
    """Связь между двумя устройствами."""

    src_id: str        # node_id источника
    dst_id: str        # node_id назначения
    label: str = ""    # описание связи (например, «LLDP», «ARP», «manual»)
    bandwidth: str = ""  # пропускная способность (если известна)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Link":
        return cls(**data)


class NetworkTopology:
    """
    Центральное хранилище топологии.

    Внутри — граф NetworkX (неориентированный) и словарь устройств.
    Граф хранит только node_id; все атрибуты — в словаре devices.
    """

    def __init__(self) -> None:
        self.graph: nx.Graph = nx.Graph()
        self.devices: dict[str, Device] = {}   # node_id → Device
        self._ip_to_id: dict[str, str] = {}    # ip → node_id (быстрый поиск)

    # ── Добавление / удаление устройств ─────────────────────────────────────

    def add_device(self, device: Device) -> str:
        """Добавить устройство в топологию. Возвращает node_id."""
        nid = device.node_id
        self.devices[nid] = device
        self._ip_to_id[device.ip] = nid
        self.graph.add_node(nid)
        logger.debug("Добавлено устройство %s (%s)", device.ip, device.device_type)
        return nid

    def remove_device(self, node_id: str) -> None:
        """Удалить устройство и все его связи."""
        if node_id not in self.devices:
            return
        dev = self.devices.pop(node_id)
        self._ip_to_id.pop(dev.ip, None)
        self.graph.remove_node(node_id)
        logger.debug("Удалено устройство %s", dev.ip)

    def get_by_ip(self, ip: str) -> Device | None:
        nid = self._ip_to_id.get(ip)
        return self.devices.get(nid) if nid else None

    # ── Связи ───────────────────────────────────────────────────────────────

    def add_link(self, src_id: str, dst_id: str, label: str = "") -> None:
        """Добавить связь между двумя устройствами."""
        if src_id == dst_id:
            return
        if not self.graph.has_edge(src_id, dst_id):
            self.graph.add_edge(src_id, dst_id, label=label)
            logger.debug("Добавлена связь %s — %s [%s]", src_id, dst_id, label)

    def remove_link(self, src_id: str, dst_id: str) -> None:
        """Удалить связь."""
        if self.graph.has_edge(src_id, dst_id):
            self.graph.remove_edge(src_id, dst_id)
            logger.debug("Удалена связь %s — %s", src_id, dst_id)

    @property
    def links(self) -> list[tuple[str, str, dict]]:
        """Список связей в формате [(src, dst, attrs), ...]."""
        return list(self.graph.edges(data=True))

    # ── Построение из результатов сканирования ───────────────────────────────

    def build_from_hosts(
        self,
        hosts: list[Device],
        arp_table: dict[str, list[tuple[str, str]]] | None = None,
    ) -> None:
        """
        Строит граф на основе списка хостов и ARP-таблицы.

        arp_table: {gateway_ip: [(ip, mac), ...]}
        Если arp_таблицы нет, связи строятся эвристически:
        все устройства подключаются к предполагаемому шлюзу (.1).
        """
        # Добавляем все хосты
        for host in hosts:
            self.add_device(host)

        # Строим связи по ARP-таблице (если есть)
        if arp_table:
            for gw_ip, entries in arp_table.items():
                gw_dev = self.get_by_ip(gw_ip)
                if not gw_dev:
                    continue
                for (ip, _mac) in entries:
                    peer = self.get_by_ip(ip)
                    if peer:
                        self.add_link(gw_dev.node_id, peer.node_id, label="ARP")
        else:
            # Эвристика: ищем устройство с типом router/switch/firewall
            # и соединяем с ним всех остальных
            hub = self._find_hub()
            if hub:
                for nid in self.devices:
                    if nid != hub.node_id:
                        self.add_link(hub.node_id, nid, label="heuristic")

        # Назначаем позиции для узлов через алгоритм spring layout
        self._assign_positions()

    def _find_hub(self) -> Device | None:
        """Ищем наиболее вероятный «центральный» узел (роутер или коммутатор)."""
        priority = ["router", "firewall", "switch", "bridge"]
        for ptype in priority:
            for dev in self.devices.values():
                if dev.device_type == ptype:
                    return dev
        # Если не нашли — берём первый
        return next(iter(self.devices.values()), None)

    def _assign_positions(self) -> None:
        """Вычисляет начальные позиции узлов.

        Пробует spring_layout (требует numpy); если numpy не установлен —
        раскладывает узлы по кругу (не требует внешних зависимостей).
        """
        if not self.graph.nodes:
            return

        try:
            pos = nx.spring_layout(self.graph, seed=42, k=2.0)
        except Exception:
            # Fallback: равномерно по кругу
            import math
            nodes = list(self.graph.nodes)
            n = len(nodes)
            pos = {}
            for i, nid in enumerate(nodes):
                angle = 2 * math.pi * i / max(n, 1)
                pos[nid] = (math.cos(angle), math.sin(angle))

        # Масштабируем до размеров canvas (800×600 пикселей)
        for nid, (x, y) in pos.items():
            if nid in self.devices:
                px = (x + 1) / 2 * 700 + 50   # [50, 750]
                py = (y + 1) / 2 * 500 + 50   # [50, 550]
                self.devices[nid].position = (px, py)

    # ── Сериализация ─────────────────────────────────────────────────────────

    def save_json(self, path: str) -> None:
        """Сохранить топологию в JSON."""
        data = {
            "devices": {nid: dev.to_dict() for nid, dev in self.devices.items()},
            "links": [
                {"src": src, "dst": dst, "label": attrs.get("label", "")}
                for src, dst, attrs in self.links
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("Топология сохранена в %s", path)

    def load_json(self, path: str) -> None:
        """Загрузить топологию из JSON."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        self.graph.clear()
        self.devices.clear()
        self._ip_to_id.clear()

        for nid, dev_data in data.get("devices", {}).items():
            dev = Device.from_dict(dev_data)
            dev.node_id = nid  # сохраняем оригинальный id
            self.add_device(dev)

        for link in data.get("links", []):
            self.add_link(link["src"], link["dst"], link.get("label", ""))

        logger.info("Топология загружена из %s (%d устройств)", path, len(self.devices))

    def export_graphml(self, path: str) -> None:
        """Экспортировать граф в формат GraphML."""
        # Добавляем атрибуты устройств в граф для экспорта
        for nid, dev in self.devices.items():
            self.graph.nodes[nid]["ip"] = dev.ip
            self.graph.nodes[nid]["type"] = dev.device_type
            self.graph.nodes[nid]["label"] = dev.hostname or dev.ip
        nx.write_graphml(self.graph, path)
        logger.info("Граф экспортирован в GraphML: %s", path)
