#!/usr/bin/env python3
"""
net_topology.py — главный файл сетевого сканера и редактора топологии.

Установка зависимостей:
    pip install scapy python-nmap networkx pyqt5 pysnmp mac-vendor-lookup

Внешние утилиты:
    - nmap (https://nmap.org/download.html) — требуется в системе
    - На Linux/Mac требуются права root/sudo для ARP-сканирования (Scapy)
    - На Windows: Npcap (https://npcap.com/) для работы Scapy

Использование:
    python net_topology.py --subnet 192.168.1.0/24 [--community public] [--no-gui] [--max-hosts 254]
"""

# ─── Стандартная библиотека ────────────────────────────────────────────────
import argparse
import logging
import sys

# ─── Внутренние модули проекта ─────────────────────────────────────────────
from scanner import NetworkScanner
from analyzer import DeviceAnalyzer
from model import NetworkTopology
from gui import run_gui

# ─── Настройка логирования ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("net_topology")


def parse_args() -> argparse.Namespace:
    """Разбор аргументов командной строки."""
    parser = argparse.ArgumentParser(
        description="Сканер сети и редактор топологии",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--subnet",
        metavar="CIDR",
        help="Сканируемая подсеть, например 192.168.1.0/24",
    )
    parser.add_argument(
        "--community",
        default="public",
        metavar="STRING",
        help="SNMP community string (по умолчанию: public)",
    )
    parser.add_argument(
        "--no-gui",
        action="store_true",
        help="Режим только CLI: вывод таблицы без графического интерфейса",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=254,
        metavar="N",
        help="Максимум хостов для сканирования (защита от зависания в больших сетях)",
    )
    parser.add_argument(
        "--load",
        metavar="FILE",
        help="Загрузить сохранённую топологию из JSON-файла вместо сканирования",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        metavar="SEC",
        help="Таймаут ответа хоста в секундах (по умолчанию: 1.0)",
    )
    return parser.parse_args()


def print_cli_table(topology: NetworkTopology) -> None:
    """Вывод найденных устройств и связей в текстовом виде (режим CLI)."""
    print("\n" + "=" * 70)
    print("  ОБНАРУЖЕННЫЕ УСТРОЙСТВА")
    print("=" * 70)
    header = f"{'IP':<18} {'MAC':<19} {'Тип':<14} {'Производитель':<22} {'Имя'}"
    print(header)
    print("-" * 70)
    for node_id, dev in topology.devices.items():
        print(
            f"{dev.ip:<18} {dev.mac or '—':<19} {dev.device_type:<14} "
            f"{dev.vendor or '—':<22} {dev.hostname or '—'}"
        )

    print("\n" + "=" * 70)
    print("  СВЯЗИ")
    print("=" * 70)
    if topology.links:
        for src, dst, attrs in topology.links:
            label = attrs.get("label", "")
            print(f"  {src}  ──  {dst}   {label}")
    else:
        print("  Связи не обнаружены (нет данных LLDP/ARP)")
    print()


def main() -> None:
    args = parse_args()

    topology = NetworkTopology()

    # ── Режим загрузки сохранённой топологии ──────────────────────────────
    if args.load:
        logger.info("Загрузка топологии из %s", args.load)
        topology.load_json(args.load)
    elif args.subnet:
        # ── Режим сканирования ─────────────────────────────────────────────
        logger.info("Начало сканирования подсети %s", args.subnet)
        scanner = NetworkScanner(
            subnet=args.subnet,
            timeout=args.timeout,
            max_hosts=args.max_hosts,
            snmp_community=args.community,
        )

        try:
            hosts = scanner.scan()
        except PermissionError as exc:
            logger.error(
                "Недостаточно прав для сканирования (нужен root/администратор): %s", exc
            )
            sys.exit(1)
        except Exception as exc:  # noqa: BLE001
            logger.error("Ошибка сканирования: %s", exc)
            sys.exit(1)

        if not hosts:
            logger.warning("Живые хосты не найдены в %s", args.subnet)
        else:
            logger.info("Найдено хостов: %d", len(hosts))

        # ── Анализ и определение типов устройств ──────────────────────────
        analyzer = DeviceAnalyzer(snmp_community=args.community)
        for host in hosts:
            analyzer.enrich(host)

        # ── Построение топологии (граф связей) ────────────────────────────
        topology.build_from_hosts(hosts, scanner.get_arp_table())
    else:
        # Ни подсеть, ни файл не указаны — запускаем GUI с пустой топологией
        logger.info("Подсеть не указана — запуск с пустой топологией")

    # ── CLI-режим ─────────────────────────────────────────────────────────
    if args.no_gui:
        print_cli_table(topology)
        return

    # ── Запуск GUI ────────────────────────────────────────────────────────
    logger.info("Запуск графического интерфейса")
    run_gui(topology)


if __name__ == "__main__":
    main()
