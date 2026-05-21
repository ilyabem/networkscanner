"""
analyzer.py — модуль анализа и классификации устройств.

Определяет тип устройства по комбинации признаков:
  1. SNMP sysDescr / sysServices (если доступен порт 161)
  2. Открытые порты (расширенная эвристика)
  3. TTL из ICMP-ответа
  4. OUI MAC-адреса (производитель)
  5. Ключевые слова в hostname / sysDescr

ДОРАБОТКА — расширенные типы и паттерны:
  Теперь различаем не просто «endpoint», а:
    windows_endpoint  — ПК/ноутбук под Windows
    linux_endpoint    — ПК/ноутбук под Linux/macOS
    windows_server    — сервер под Windows Server
    linux_server      — сервер под Linux
    printer           — сетевой принтер
  Сетевое оборудование делится как прежде: router / switch / bridge / firewall.
  Если тип не определён — unknown.
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
        CommunityData, ContextData, ObjectIdentity,
        ObjectType, SnmpEngine, UdpTransportTarget, getCmd,
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logger.warning("pysnmp не установлен. SNMP-опрос недоступен.")

OID_SYS_DESCR    = "1.3.6.1.2.1.1.1.0"
OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0"
OID_SYS_NAME     = "1.3.6.1.2.1.1.5.0"

# ─── Расширенный список типов ────────────────────────────────────────────────
# Новые типы для точной классификации конечных точек
EXTENDED_DEVICE_TYPES = [
    "router",
    "switch",
    "bridge",
    "firewall",
    "windows_server",   # Windows Server 2012/2016/2019/2022
    "linux_server",     # Linux-сервер (Ubuntu Server, CentOS, Debian...)
    "server",           # сервер (ОС не определена)
    "windows_endpoint", # ПК / ноутбук под Windows
    "linux_endpoint",   # ПК / ноутбук под Linux или macOS
    "printer",          # сетевой принтер / МФУ
    "endpoint",         # конечная точка (ОС не определена)
    "unknown",
]

# ─── Паттерны по ключевым словам ────────────────────────────────────────────
# Порядок важен: более специфичные паттерны — раньше.
# Каждая запись: (список ключевых слов, тип, вес)
KEYWORD_PATTERNS: list[tuple[list[str], str, float]] = [
    # ── Сетевое оборудование ────────────────────────────────────────────────
    (["pfsense", "opnsense", "fortigate", "fortifw", "checkpoint",
      "watchguard", "sophos", "junos srx", "palo alto", "asa",
      "cisco asa", "netscreen"],                          "firewall",         10),
    (["cisco ios", "cisco nx-os", "cisco ios-xe", "ios software",
      "junos", "routeros", "mikrotik", "edgeos", "vyos",
      "openwrt", "dd-wrt", "маршрутизатор"],              "router",           10),
    (["catalyst", "procurve", "aruba", "hp switch", "netgear gs",
      "netgear fs", "d-link switch", "tp-link switch",
      "juniper ex", "cisco sg", "cisco sf",
      "коммутатор", "switch software"],                   "switch",           10),
    (["bridge", "бридж"],                                 "bridge",           8),

    # ── Windows Server ───────────────────────────────────────────────────────
    (["windows server 2022", "windows server 2019",
      "windows server 2016", "windows server 2012",
      "windows server 2008", "microsoft windows server"],  "windows_server",   12),

    # ── Linux Server (без desktop-окружения, серверные дистрибутивы) ─────────
    (["ubuntu server", "ubuntu 20.04 lts", "ubuntu 22.04 lts",
      "ubuntu 24.04 lts", "centos linux", "red hat enterprise",
      "rhel", "almalinux", "rocky linux", "oracle linux",
      "debian gnu/linux", "debian 11", "debian 12",
      "debian 10", "suse linux enterprise", "sles",
      "freebsd", "proxmox", "esxi", "vmware esxi",
      "linux server"],                                     "linux_server",     12),

    # ── macOS / Linux Desktop ────────────────────────────────────────────────
    (["darwin", "macos", "mac os x", "apple mac"],         "linux_endpoint",   9),
    (["ubuntu desktop", "fedora", "arch linux", "manjaro",
      "pop!_os", "elementary os", "linux mint", "kubuntu",
      "xubuntu", "lubuntu", "zorin"],                      "linux_endpoint",   9),

    # ── Windows Desktop ──────────────────────────────────────────────────────
    (["windows 11", "windows 10", "windows 8", "windows 7",
      "windows vista", "windows xp", "microsoft windows 1",
      "workstation"],                                       "windows_endpoint", 9),

    # ── Принтеры и МФУ ───────────────────────────────────────────────────────
    (["printer", "принтер", "laserjet", "officejet", "mfp",
      "мфу", "ricoh", "kyocera", "xerox", "canon printer",
      "epson", "brother mfc", "hp color"],                 "printer",          11),

    # ── Общий Linux/Unix (если не попало выше) ───────────────────────────────
    (["linux", "unix", "nginx", "apache", "postfix",
      "openssh", "snmpd"],                                 "linux_server",     5),

    # ── Общий Windows (если не попало выше) ──────────────────────────────────
    (["windows", "microsoft", "msrpc", "netbios"],         "windows_endpoint", 4),
]

# ─── Эвристика по портам ────────────────────────────────────────────────────
# port → [(тип, вес), ...]  — взвешенное голосование
PORT_WEIGHTS: dict[int, list[tuple[str, float]]] = {
    # Сетевое оборудование
    23:   [("router", 4), ("switch", 3)],          # Telnet
    161:  [("router", 5), ("switch", 5)],           # SNMP
    179:  [("router", 6)],                          # BGP
    520:  [("router", 4)],                          # RIP
    # Серверы
    21:   [("linux_server", 3), ("server", 2)],     # FTP
    22:   [("linux_server", 3), ("router", 2)],     # SSH
    25:   [("linux_server", 5), ("windows_server", 4)],  # SMTP
    53:   [("linux_server", 3), ("router", 2)],     # DNS
    67:   [("router", 3), ("linux_server", 2)],     # DHCP
    80:   [("linux_server", 3), ("windows_server", 3), ("printer", 2)],
    110:  [("linux_server", 4), ("windows_server", 4)],  # POP3
    143:  [("linux_server", 4), ("windows_server", 4)],  # IMAP
    389:  [("windows_server", 5), ("linux_server", 4)],  # LDAP
    443:  [("linux_server", 3), ("windows_server", 3)],  # HTTPS
    445:  [("windows_server", 4), ("windows_endpoint", 3)],  # SMB
    636:  [("windows_server", 4), ("linux_server", 4)],  # LDAPS
    993:  [("linux_server", 4), ("windows_server", 3)],  # IMAPS
    995:  [("linux_server", 4), ("windows_server", 3)],  # POP3S
    1433: [("windows_server", 6)],                  # MSSQL
    1521: [("linux_server", 5), ("windows_server", 4)],  # Oracle
    3306: [("linux_server", 6), ("windows_server", 3)],  # MySQL
    5432: [("linux_server", 6)],                    # PostgreSQL
    5985: [("windows_server", 5), ("windows_endpoint", 3)],  # WinRM HTTP
    5986: [("windows_server", 5)],                  # WinRM HTTPS
    6379: [("linux_server", 5)],                    # Redis
    8080: [("linux_server", 3), ("windows_server", 3)],
    8443: [("linux_server", 3), ("windows_server", 3)],
    27017:[("linux_server", 5)],                    # MongoDB
    # Windows endpoint / RDP
    3389: [("windows_endpoint", 5), ("windows_server", 4)],  # RDP
    # Принтеры
    9100: [("printer", 8)],                         # JetDirect (RAW print)
    515:  [("printer", 7)],                         # LPD
    631:  [("printer", 6)],                         # IPP (CUPS)
}

# Порты-«убийцы» — если открыт, тип почти точно определён
DEFINITIVE_PORTS: dict[int, str] = {
    9100: "printer",
    515:  "printer",
    1433: "windows_server",
    5985: "windows_server",
}

# ─── TTL → тип ───────────────────────────────────────────────────────────────
# TTL 64  → Linux/macOS (endpoint или server)
# TTL 128 → Windows
# TTL 255 → сетевое оборудование Cisco/HP
TTL_HINTS: list[tuple[range, str, float]] = [
    (range(63, 66),  "linux_server",     1.5),  # 64 — Linux default
    (range(127, 130),"windows_endpoint", 1.5),  # 128 — Windows default
    (range(250, 256), "router",          2.0),  # 255 — Cisco/HP
]

# ─── OUI производителя → тип ─────────────────────────────────────────────────
VENDOR_WEIGHTS: list[tuple[list[str], str, float]] = [
    # Сетевое оборудование
    (["cisco",  "juniper", "mikrotik", "ubiquiti", "aruba",
      "zyxel",  "d-link",  "tp-link",  "netgear",  "zyxel",
      "extreme networks", "brocade", "allied telesis"],    "router",           4),
    (["hewlett packard enterprise", "hp enterprise",
      "fortinet", "watchguard", "palo alto networks",
      "checkpoint"],                                       "firewall",         4),
    # Серверы и ПК
    (["dell", "supermicro", "intel corporate",
      "ibm", "lenovo", "hewlett-packard"],                 "linux_server",     2),
    (["apple"],                                            "linux_endpoint",   3),
    (["samsung", "lg electronics", "huawei"],              "windows_endpoint", 2),
    # Принтеры
    (["seiko epson", "canon", "ricoh", "kyocera",
      "xerox", "lexmark", "brother industries"],           "printer",          5),
    # VMware / виртуалки → скорее всего сервер
    (["vmware", "oracle virtualbox", "parallels",
      "xensource"],                                        "linux_server",     3),
]


class DeviceAnalyzer:
    """Обогащает и классифицирует Device-объекты."""

    def __init__(self, snmp_community: str = "public", snmp_timeout: float = 1.0) -> None:
        self.snmp_community = snmp_community
        self.snmp_timeout   = snmp_timeout

    def enrich(self, device: "Device") -> None:
        """
        Запускает все доступные методы определения типа.
        Использует взвешенное голосование — побеждает тип с наибольшей суммой весов.
        """
        scores: dict[str, float] = {}

        def vote(dtype: str, weight: float) -> None:
            scores[dtype] = scores.get(dtype, 0) + weight

        # 1. SNMP (самый надёжный источник, если доступен)
        if SNMP_AVAILABLE and 161 in device.open_ports:
            snmp_result = self._query_snmp(device)
            if snmp_result:
                dtype, weight, sys_name = snmp_result
                vote(dtype, weight)
                if sys_name and not device.hostname:
                    device.hostname = sys_name

        # 2. Ключевые слова в hostname
        if device.hostname:
            self._keywords_vote(device.hostname, scores)

        # 3. Открытые порты
        self._ports_vote(device.open_ports, scores)

        # 4. TTL
        if device.ttl is not None:
            for ttl_range, dtype, w in TTL_HINTS:
                if device.ttl in ttl_range:
                    vote(dtype, w)

        # 5. Производитель OUI
        if device.vendor:
            vendor_lower = device.vendor.lower()
            for keywords, dtype, w in VENDOR_WEIGHTS:
                if any(kw in vendor_lower for kw in keywords):
                    vote(dtype, w)
                    break

        # Выбираем победителя
        if scores:
            device.device_type = max(scores, key=lambda k: scores[k])
        else:
            device.device_type = "unknown"

        logger.info(
            "%-18s → %-18s  scores=%s",
            device.ip,
            device.device_type,
            {k: round(v, 1) for k, v in
             sorted(scores.items(), key=lambda x: -x[1])[:4]},
        )

    # ─── SNMP ───────────────────────────────────────────────────────────────

    def _query_snmp(self, device: "Device") -> tuple[str, float, str] | None:
        """
        SNMP GET sysDescr + sysServices + sysName.
        Возвращает (тип, вес, имя_хоста) или None при ошибке.
        """
        try:
            result = self._snmp_get(device.ip,
                                    [OID_SYS_DESCR, OID_SYS_SERVICES, OID_SYS_NAME])
        except Exception as exc:
            logger.debug("SNMP %s: %s", device.ip, exc)
            return None

        device.snmp_info = result
        sys_descr    = result.get(OID_SYS_DESCR, "").lower()
        sys_services = result.get(OID_SYS_SERVICES, "0")
        sys_name     = result.get(OID_SYS_NAME, "")

        # Сначала пробуем ключевые слова в sysDescr (точнее sysServices)
        kw_type = self._match_keywords(sys_descr)
        if kw_type:
            return kw_type, 10.0, sys_name

        # Fallback: sysServices битовая маска RFC 1213
        dtype = parse_snmp_services(sys_services)
        if dtype:
            return dtype, 7.0, sys_name

        return None

    def _snmp_get(self, ip: str, oids: list[str]) -> dict[str, str]:
        result: dict[str, str] = {}
        engine    = SnmpEngine()
        community = CommunityData(self.snmp_community, mpModel=1)
        transport = UdpTransportTarget((ip, 161),
                                       timeout=self.snmp_timeout, retries=1)
        context   = ContextData()
        for oid in oids:
            error_ind, error_st, _, var_binds = next(
                getCmd(engine, community, transport, context,
                       ObjectType(ObjectIdentity(oid)))
            )
            if not error_ind and not error_st:
                for vb in var_binds:
                    result[oid] = str(vb[1])
        return result

    # ─── Ключевые слова ─────────────────────────────────────────────────────

    @staticmethod
    def _match_keywords(text: str) -> str | None:
        """Возвращает тип по первому совпадению в KEYWORD_PATTERNS."""
        text_lower = text.lower()
        best_type: str | None = None
        best_weight: float    = 0
        for keywords, dtype, weight in KEYWORD_PATTERNS:
            if any(kw in text_lower for kw in keywords):
                if weight > best_weight:
                    best_type   = dtype
                    best_weight = weight
        return best_type

    @staticmethod
    def _keywords_vote(text: str, scores: dict[str, float]) -> None:
        """Добавляет веса в scores по всем совпадениям ключевых слов."""
        text_lower = text.lower()
        for keywords, dtype, weight in KEYWORD_PATTERNS:
            if any(kw in text_lower for kw in keywords):
                scores[dtype] = scores.get(dtype, 0) + weight

    # ─── Порты ──────────────────────────────────────────────────────────────

    @staticmethod
    def _ports_vote(open_ports: list[int], scores: dict[str, float]) -> None:
        port_set = set(open_ports)
        # Дефинитивные порты — очень высокий вес
        for port, dtype in DEFINITIVE_PORTS.items():
            if port in port_set:
                scores[dtype] = scores.get(dtype, 0) + 15
                return  # дефинитивный порт — дальше не смотрим
        # Взвешенное голосование
        for port in port_set:
            for dtype, weight in PORT_WEIGHTS.get(port, []):
                scores[dtype] = scores.get(dtype, 0) + weight


# ─── Публичные функции для тестов ────────────────────────────────────────────

def classify_by_ports(open_ports: list[int]) -> str | None:
    """Определяет тип по портам. Публичная обёртка для тестов."""
    scores: dict[str, float] = {}
    DeviceAnalyzer._ports_vote(open_ports, scores)
    return max(scores, key=lambda k: scores[k]) if scores else None


def parse_snmp_services(sys_services_value: str) -> str | None:
    """
    Парсит sysServices RFC 1213 и возвращает тип устройства.
    Публичная функция, используется в тестах.

    Битовая маска:
      bit1 (2)  — datalink/L2 → switch
      bit2 (4)  — internet/L3 routing → router
      bit6 (64) — application/L7 → server
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
        return "linux_server"   # уточнённый тип вместо просто "server"
    return None


def classify_by_keywords(text: str) -> str | None:
    """Публичная обёртка для тестов."""
    return DeviceAnalyzer._match_keywords(text)
