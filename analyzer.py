"""
analyzer.py — модуль анализа и классификации устройств.

Определяет тип устройства по комбинации признаков:
  1. SNMP sysDescr / sysServices (если доступен порт 161)
  2. Открытые порты (эвристика)
  3. TTL из ICMP-ответа (косвенный признак ОС)
  4. OUI MAC-адреса (производитель)
  5. Ключевые слова в hostname

Если определить тип не удалось — устанавливает "unknown".
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from model import Device

logger = logging.getLogger("analyzer")

# ─── Попытка импорта pysnmp ──────────────────────────────────────────────────
try:
    from pysnmp.hlapi import (  # type: ignore
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logger.warning("pysnmp не установлен. SNMP-опрос недоступен.")

# ─── OID для SNMP-запросов ───────────────────────────────────────────────────
OID_SYS_DESCR    = "1.3.6.1.2.1.1.1.0"   # sysDescr — описание системы
OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0"   # sysServices — битовая маска сервисов
OID_SYS_NAME     = "1.3.6.1.2.1.1.5.0"   # sysName — имя устройства

# ─── Эвристики по портам ─────────────────────────────────────────────────────
# Порт → набор возможных типов (от более специфичного к менее)
PORT_TYPE_MAP: dict[int, list[str]] = {
    22:   ["server", "router"],    # SSH: сервер или сетевое оборудование
    23:   ["router", "switch"],    # Telnet: чаще сетевое оборудование
    25:   ["server"],              # SMTP: почтовый сервер
    53:   ["server", "router"],    # DNS
    67:   ["router", "server"],    # DHCP
    80:   ["server"],              # HTTP
    161:  ["router", "switch"],    # SNMP: сетевое оборудование
    443:  ["server"],              # HTTPS
    445:  ["server", "endpoint"],  # SMB: Windows-файловый сервер или ПК
    3389: ["endpoint", "server"],  # RDP: рабочий стол (Windows)
    8080: ["server"],
    8443: ["server"],
}

# Ключевые слова для определения типа по sysDescr / hostname
KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["cisco", "ios", "router", "маршрутизатор"],    "router"),
    (["mikrotik", "routeros"],                        "router"),
    (["juniper", "junos"],                            "router"),
    (["pfsense", "opnsense", "firewall", "fortigate"], "firewall"),
    (["switch", "коммутатор", "catalyst", "procurve", "aruba"], "switch"),
    (["bridge", "бридж"],                             "bridge"),
    (["linux", "ubuntu", "debian", "centos", "freebsd",
      "windows server", "nginx", "apache", "postfix"], "server"),
    (["windows", "printer", "принтер"],               "endpoint"),
]

# Эвристика по TTL (Linux ≈ 64, Windows ≈ 128, сетевое оборудование ≈ 255)
TTL_TYPE_HINTS: list[tuple[range, str]] = [
    (range(60, 70),  "server"),      # Linux/Unix
    (range(120, 135), "endpoint"),   # Windows
    (range(250, 256), "router"),     # Cisco/HP networking
]

# Ключевые слова в OUI-производителе
VENDOR_MAP: list[tuple[list[str], str]] = [
    (["cisco", "juniper", "mikrotik", "ubiquiti", "aruba", "zyxel", "d-link"], "router"),
    (["hewlett", "hp", "netgear", "tp-link", "tplink"], "switch"),
    (["fortinet", "watchguard", "palo alto", "checkpoint"], "firewall"),
    (["dell", "hp inc", "lenovo", "apple", "samsung", "intel"], "endpoint"),
    (["vmware", "oracle", "supermicro"], "server"),
]

# Порты, которые почти гарантируют «это сервер»
SERVER_DEFINITIVE_PORTS = {25, 110, 143, 587, 993, 995, 3306, 5432, 6379, 27017}


class DeviceAnalyzer:
    """Обогащает и классифицирует Device-объекты."""

    def __init__(self, snmp_community: str = "public", snmp_timeout: float = 1.0) -> None:
        self.snmp_community = snmp_community
        self.snmp_timeout = snmp_timeout

    # ─── Главный метод обогащения ────────────────────────────────────────────

    def enrich(self, device: "Device") -> None:
        """
        Запускает все доступные методы определения типа устройства
        и выставляет device.device_type.
        """
        scores: dict[str, float] = {}  # тип → вес

        # 1. SNMP (наиболее надёжный источник)
        if SNMP_AVAILABLE and 161 in device.open_ports:
            snmp_type = self._classify_by_snmp(device)
            if snmp_type:
                scores[snmp_type] = scores.get(snmp_type, 0) + 10

        # 2. Открытые порты
        port_type = self._classify_by_ports(device.open_ports)
        if port_type:
            scores[port_type] = scores.get(port_type, 0) + 5

        # 3. TTL
        if device.ttl is not None:
            ttl_type = self._classify_by_ttl(device.ttl)
            if ttl_type:
                scores[ttl_type] = scores.get(ttl_type, 0) + 2

        # 4. Производитель (OUI)
        if device.vendor:
            vendor_type = self._classify_by_vendor(device.vendor)
            if vendor_type:
                scores[vendor_type] = scores.get(vendor_type, 0) + 3

        # 5. Hostname / имя
        if device.hostname:
            name_type = self._classify_by_keywords(device.hostname)
            if name_type:
                scores[name_type] = scores.get(name_type, 0) + 4

        # Выбираем тип с максимальным весом
        if scores:
            device.device_type = max(scores, key=lambda k: scores[k])
        else:
            device.device_type = "unknown"

        logger.info(
            "%-18s → %-10s (scores: %s)",
            device.ip,
            device.device_type,
            {k: round(v, 1) for k, v in sorted(scores.items(), key=lambda x: -x[1])},
        )

    # ─── SNMP ────────────────────────────────────────────────────────────────

    def _classify_by_snmp(self, device: "Device") -> str | None:
        """
        Опрашивает устройство по SNMP v1/v2c.
        Читает sysDescr и sysServices, классифицирует по ключевым словам и битам.
        """
        try:
            result = self._snmp_get(device.ip, [OID_SYS_DESCR, OID_SYS_SERVICES, OID_SYS_NAME])
        except Exception as exc:  # noqa: BLE001
            logger.debug("SNMP ошибка %s: %s", device.ip, exc)
            return None

        sys_descr    = result.get(OID_SYS_DESCR, "").lower()
        sys_services = result.get(OID_SYS_SERVICES, "0")
        sys_name     = result.get(OID_SYS_NAME, "")

        device.snmp_info = result
        if sys_name and not device.hostname:
            device.hostname = sys_name

        # sysServices — битовая маска RFC 1213:
        # bit 0 (1): physical (L1), bit 1 (2): datalink/subnet (L2)
        # bit 2 (4): internet (L3), bit 3 (8): end-to-end (L4), bit 6 (64): applications
        try:
            svc = int(sys_services)
        except ValueError:
            svc = 0

        # Приоритет: L3 (маршрутизатор), L2 (коммутатор), L7 (сервер)
        if svc & 4 and not (svc & 64):
            # Routing включён, приложений нет — скорее всего роутер
            device_type = "router"
        elif svc & 2 and not (svc & 4):
            # Только L2 — коммутатор
            device_type = "switch"
        elif svc & 64:
            # Приложения (L7) — сервер или конечная точка
            device_type = "server"
        else:
            device_type = None

        # Уточнение по sysDescr (ключевые слова важнее битовой маски)
        kw_type = self._classify_by_keywords(sys_descr)
        if kw_type:
            device_type = kw_type

        return device_type

    def _snmp_get(self, ip: str, oids: list[str]) -> dict[str, str]:
        """
        Выполняет SNMP GET-запрос и возвращает словарь {oid: value}.
        Использует pysnmp v4 (hlapi).
        """
        result: dict[str, str] = {}
        engine = SnmpEngine()
        community = CommunityData(self.snmp_community, mpModel=1)  # v2c
        transport = UdpTransportTarget(
            (ip, 161),
            timeout=self.snmp_timeout,
            retries=1,
        )
        context = ContextData()

        for oid in oids:
            obj_type = ObjectType(ObjectIdentity(oid))
            error_indication, error_status, _, var_binds = next(
                getCmd(engine, community, transport, context, obj_type)
            )
            if error_indication or error_status:
                continue
            for var_bind in var_binds:
                result[oid] = str(var_bind[1])

        return result

    # ─── Эвристика по портам ────────────────────────────────────────────────

    @staticmethod
    def _classify_by_ports(open_ports: list[int]) -> str | None:
        """Определяет тип по открытым портам с взвешенным голосованием."""
        if not open_ports:
            return None

        port_set = set(open_ports)

        # Порты, однозначно указывающие на сервер
        if port_set & SERVER_DEFINITIVE_PORTS:
            return "server"

        # Голосование: счётчик для каждого возможного типа
        votes: dict[str, int] = {}
        for port in port_set:
            for candidate_type in PORT_TYPE_MAP.get(port, []):
                votes[candidate_type] = votes.get(candidate_type, 0) + 1

        if not votes:
            return None

        # Тип с наибольшим числом голосов
        return max(votes, key=lambda k: votes[k])

    # ─── Эвристика по TTL ────────────────────────────────────────────────────

    @staticmethod
    def _classify_by_ttl(ttl: int) -> str | None:
        for ttl_range, device_type in TTL_TYPE_HINTS:
            if ttl in ttl_range:
                return device_type
        return None

    # ─── Эвристика по производителю ─────────────────────────────────────────

    @staticmethod
    def _classify_by_vendor(vendor: str) -> str | None:
        vendor_lower = vendor.lower()
        for keywords, device_type in VENDOR_MAP:
            if any(kw in vendor_lower for kw in keywords):
                return device_type
        return None

    # ─── Ключевые слова ──────────────────────────────────────────────────────

    @staticmethod
    def _classify_by_keywords(text: str) -> str | None:
        text_lower = text.lower()
        for keywords, device_type in KEYWORD_MAP:
            if any(kw in text_lower for kw in keywords):
                return device_type
        return None


# ─── Публичные вспомогательные функции (используются в тестах) ───────────────

def classify_by_ports(open_ports: list[int]) -> str | None:
    """Обёртка для тестирования."""
    return DeviceAnalyzer._classify_by_ports(open_ports)


def parse_snmp_services(sys_services_value: str) -> str | None:
    """
    Парсит значение sysServices (строка с числом) и возвращает
    предполагаемый тип устройства.

    Используется в unit-тестах напрямую.
    """
    try:
        svc = int(sys_services_value)
    except (ValueError, TypeError):
        return None

    if svc & 4 and not (svc & 64):
        return "router"
    if svc & 2 and not (svc & 4) and not (svc & 64):
        return "switch"
    if svc & 64:
        return "server"
    return None
