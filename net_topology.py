#!/usr/bin/env python3
"""
net_topology.py — главный файл сетевого сканера и редактора топологии.

Установка зависимостей:
    pip install -r requirements.txt
    pip install numpy pysnmp

Внешние утилиты:
    - nmap (https://nmap.org/download.html) — требуется в системе
    - На Linux/Mac: права root/sudo для ARP-сканирования
    - На Windows: Npcap (https://npcap.com/) для работы Scapy

Использование (одна подсеть):
    python net_topology.py --subnet 192.168.1.0/24

Использование (несколько подсетей):
    python net_topology.py --subnets 192.168.1.0/24 10.0.0.0/24
    python net_topology.py --subnets 192.168.1.0/24,10.0.0.0/24

Дополнительные флаги:
    --community STRING   SNMP community string (по умолчанию: public)
    --no-gui             Только CLI: таблица без графики
    --max-hosts N        Ограничение числа хостов на подсеть
    --load FILE          Загрузить сохранённую топологию из JSON
    --timeout SEC        Таймаут ответа хоста (по умолчанию: 1.0)
    --parallel           Сканировать подсети параллельно (ThreadPoolExecutor)
"""

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner import NetworkScanner
from analyzer import DeviceAnalyzer
from model import NetworkTopology, Device
from gui import run_gui

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("net_topology")


# ─── Разбор аргументов ───────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Сканер сети и редактор топологии (поддержка нескольких подсетей)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Группа подсетей: --subnet (одна) или --subnets (несколько)
    subnet_group = parser.add_mutually_exclusive_group()
    subnet_group.add_argument(
        "--subnet", metavar="CIDR",
        help="Одна сканируемая подсеть, например 192.168.1.0/24",
    )
    subnet_group.add_argument(
        "--subnets", nargs="+", metavar="CIDR",
        help="Несколько подсетей через пробел или запятую: "
             "--subnets 192.168.1.0/24 10.0.0.0/24  "
             "или  --subnets 192.168.1.0/24,10.0.0.0/24",
    )

    parser.add_argument("--community", default="public", metavar="STRING",
                        help="SNMP community string (по умолчанию: public)")
    parser.add_argument("--no-gui", action="store_true",
                        help="Только CLI: вывод таблицы без GUI")
    parser.add_argument("--max-hosts", type=int, default=254, metavar="N",
                        help="Макс. хостов на подсеть (защита от зависания)")
    parser.add_argument("--load", metavar="FILE",
                        help="Загрузить топологию из JSON-файла")
    parser.add_argument("--timeout", type=float, default=1.0, metavar="SEC",
                        help="Таймаут ответа хоста (по умолчанию: 1.0)")
    parser.add_argument("--parallel", action="store_true",
                        help="Сканировать подсети параллельно")
    return parser.parse_args()


# ─── Нормализация списка подсетей ────────────────────────────────────────────

def resolve_subnets(args: argparse.Namespace) -> list[str]:
    """
    Собирает список подсетей из аргументов.
    Поддерживает: --subnet X, --subnets X Y, --subnets X,Y,Z
    """
    if args.subnet:
        return [args.subnet]
    if args.subnets:
        result = []
        for item in args.subnets:
            # Разбиваем по запятой на случай "192.168.1.0/24,10.0.0.0/24"
            for part in item.split(","):
                part = part.strip()
                if part:
                    result.append(part)
        return result
    return []


# ─── Сканирование одной подсети ───────────────────────────────────────────────

def scan_subnet(
    subnet: str,
    community: str,
    timeout: float,
    max_hosts: int,
) -> tuple[str, list[Device], dict]:
    """
    Сканирует одну подсеть и возвращает кортеж:
        (subnet, hosts_list, arp_table)

    Используется как для последовательного, так и для параллельного запуска.
    """
    logger.info("▶ Сканирование подсети %s", subnet)
    scanner = NetworkScanner(
        subnet=subnet,
        timeout=timeout,
        max_hosts=max_hosts,
        snmp_community=community,
    )
    hosts = scanner.scan()
    logger.info("◀ Подсеть %s: найдено %d хостов", subnet, len(hosts))

    # Обогащаем каждый хост: тип устройства, SNMP, vendor
    analyzer = DeviceAnalyzer(snmp_community=community)
    for host in hosts:
        analyzer.enrich(host)

    return subnet, hosts, scanner.get_arp_table()


# ─── CLI-вывод таблицы ───────────────────────────────────────────────────────

def print_cli_table(topology: NetworkTopology) -> None:
    """
    Выводит найденные устройства и связи в текстовом виде.
    Мультиинтерфейсные устройства помечены звёздочкой (*).
    """
    print("\n" + "=" * 80)
    print("  ОБНАРУЖЕННЫЕ УСТРОЙСТВА")
    print("  * = мультиинтерфейсное устройство (несколько IP/подсетей)")
    print("=" * 80)
    header = f"{'*':<2} {'IP':<18} {'MAC':<19} {'Тип':<12} {'Производитель':<22} {'Имя хоста'}"
    print(header)
    print("-" * 80)

    for dev in topology.devices.values():
        mark = "*" if dev.is_multihomed else " "
        print(
            f"{mark:<2} {dev.ip:<18} {dev.mac or '—':<19} "
            f"{dev.device_type:<12} {dev.vendor or '—':<22} "
            f"{dev.hostname or '—'}"
        )
        # Для мультиинтерфейсных выводим все интерфейсы
        if dev.is_multihomed:
            for iface in dev.interfaces:
                if iface.ip != dev.ip:
                    iname = f" ({iface.iface_name})" if iface.iface_name else ""
                    sname = f" [{iface.subnet}]"     if iface.subnet     else ""
                    print(f"   ↳ {iface.ip}{iname}{sname}")

    print("\n" + "=" * 80)
    print("  СВЯЗИ")
    print("=" * 80)
    if topology.links:
        for src, dst, attrs in topology.links:
            src_dev = topology.devices.get(src)
            dst_dev = topology.devices.get(dst)
            src_ip  = src_dev.ip if src_dev else src
            dst_ip  = dst_dev.ip if dst_dev else dst
            label   = attrs.get("label", "")
            print(f"  {src_ip:<20}  ──  {dst_ip:<20}  [{label}]")
    else:
        print("  Связи не обнаружены")
    print()


# ─── Точка входа ─────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()
    topology = NetworkTopology()

    # ── Режим загрузки из файла ───────────────────────────────────────────────
    if args.load:
        logger.info("Загрузка топологии из %s", args.load)
        topology.load_json(args.load)

    else:
        subnets = resolve_subnets(args)

        if not subnets:
            # Ни подсеть, ни файл не указаны → запуск GUI с пустой топологией
            logger.info("Подсети не указаны — запуск с пустой топологией")

        elif len(subnets) == 1:
            # ── Одна подсеть (обратная совместимость) ────────────────────────
            subnet = subnets[0]
            logger.info("Сканирование подсети %s", subnet)
            try:
                _, hosts, arp_table = scan_subnet(
                    subnet, args.community, args.timeout, args.max_hosts
                )
            except PermissionError as exc:
                logger.error("Недостаточно прав (нужен root/администратор): %s", exc)
                sys.exit(1)
            except Exception as exc:
                logger.error("Ошибка сканирования: %s", exc)
                sys.exit(1)

            if not hosts:
                logger.warning("Живые хосты не найдены в %s", subnet)

            topology.build_from_hosts(hosts, arp_table, subnet=subnet)

        else:
            # ── Несколько подсетей ────────────────────────────────────────────
            logger.info("Сканирование %d подсетей: %s", len(subnets), subnets)
            subnet_results = []

            if args.parallel:
                # Параллельное сканирование через ThreadPoolExecutor
                logger.info("Режим: параллельное сканирование")
                with ThreadPoolExecutor(max_workers=len(subnets)) as executor:
                    futures = {
                        executor.submit(
                            scan_subnet, s, args.community, args.timeout, args.max_hosts
                        ): s
                        for s in subnets
                    }
                    for future in as_completed(futures):
                        s = futures[future]
                        try:
                            subnet_results.append(future.result())
                        except PermissionError as exc:
                            logger.error("Нет прав для %s: %s", s, exc)
                        except Exception as exc:
                            logger.error("Ошибка сканирования %s: %s", s, exc)
            else:
                # Последовательное сканирование
                logger.info("Режим: последовательное сканирование")
                for subnet in subnets:
                    try:
                        subnet_results.append(
                            scan_subnet(subnet, args.community, args.timeout, args.max_hosts)
                        )
                    except PermissionError as exc:
                        logger.error("Нет прав для %s: %s", subnet, exc)
                    except Exception as exc:
                        logger.error("Ошибка сканирования %s: %s", subnet, exc)

            if not subnet_results:
                logger.error("Ни одна подсеть не была успешно просканирована")
                sys.exit(1)

            # Строим топологию с объединением по MAC
            topology.build_from_multi_subnet(subnet_results)

    # ── CLI-режим ─────────────────────────────────────────────────────────────
    if args.no_gui:
        print_cli_table(topology)
        return

    # ── GUI ───────────────────────────────────────────────────────────────────
    logger.info("Запуск графического интерфейса")
    run_gui(topology)


if __name__ == "__main__":
    main()
