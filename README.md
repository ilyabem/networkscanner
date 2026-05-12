# Сканер и редактор топологии сети

Инструмент для обнаружения устройств в сети, классификации их типов и построения интерактивной топологической схемы с возможностью редактирования.

---

## Структура проекта

```
net_topology/
├── net_topology.py   # Главный файл (точка входа)
├── scanner.py        # Сканирование сети (ARP + nmap)
├── analyzer.py       # Классификация устройств (SNMP, порты, TTL, OUI)
├── model.py          # Модель данных (Device, NetworkTopology)
├── gui.py            # Графический интерфейс (PyQt5)
├── requirements.txt  # Зависимости
└── tests/
    └── test_topology.py   # Юнит-тесты (pytest)
```

---

## Установка

### Шаг 1 — Системные зависимости

#### Linux (Debian / Ubuntu)

```bash
# nmap — сканер портов (обязателен)
sudo apt install -y nmap

# Библиотеки Qt для работы GUI
sudo apt install -y \
    libxcb-cursor0 \
    libxcb-xinerama0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-randr0 \
    libxcb-render-util0 \
    libxcb-shape0 \
    libxcb-xfixes0 \
    libxcb-xkb1 \
    libxkbcommon-x11-0 \
    libgl1 \
    libglib2.0-0
```

#### macOS

```bash
brew install nmap
```

#### Windows

- Скачать и установить **nmap**: https://nmap.org/download.html
- Скачать и установить **Npcap** (нужен для Scapy): https://npcap.com/
- При установке Npcap отметить галочку «WinPcap API-compatible mode»

---

### Шаг 2 — Виртуальное окружение Python

Виртуальное окружение изолирует зависимости проекта от системного Python и защищает от конфликтов пакетов.

#### Linux / macOS

```bash
# Создать окружение в папке venv/
python3 -m venv venv

# Активировать
source venv/bin/activate

# Деактивировать (когда закончили работу)
deactivate
```

#### Windows

```bat
:: Создать окружение
python -m venv venv

:: Активировать
venv\Scripts\activate.bat

:: Деактивировать
deactivate
```

> После активации в начале строки терминала появится `(venv)` — это значит, что окружение активно и все команды `pip` и `python` работают внутри него.

---

### Шаг 3 — Python-зависимости

```bash
# Основные зависимости из файла
pip install -r requirements.txt

# Дополнительные пакеты (рекомендуется)
pip install numpy pysnmp
```

Что устанавливается:

| Пакет | Назначение |
|---|---|
| `python-nmap` | Обёртка над системным nmap |
| `scapy` | ARP-сканирование (L2) |
| `networkx` | Граф топологии и layout |
| `PyQt5` | Графический интерфейс |
| `pysnmp` | SNMP-опрос устройств |
| `mac-vendor-lookup` | Определение производителя по MAC |
| `numpy` | Требуется для spring_layout в NetworkX |
| `pytest` | Запуск юнит-тестов |

---

### Полная установка одной командой (Linux/Ubuntu)

```bash
# Системные пакеты
sudo apt install -y nmap \
    libxcb-cursor0 libxcb-xinerama0 libxcb-icccm4 libxcb-image0 \
    libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 \
    libxcb-xfixes0 libxcb-xkb1 libxkbcommon-x11-0 libgl1 libglib2.0-0

# Виртуальное окружение и зависимости
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install numpy pysnmp
```

---

## Использование

### Режим GUI (с автоматическим сканированием)

```bash
python net_topology.py --subnet 192.168.1.0/24
```

### Только CLI (без графики)

```bash
python net_topology.py --subnet 192.168.1.0/24 --no-gui
```

### С SNMP community string

```bash
python net_topology.py --subnet 192.168.1.0/24 --community mycommunity
```

### Загрузить сохранённую топологию

```bash
python net_topology.py --load topology.json
```

### Только GUI (без сканирования)

```bash
python net_topology.py
```

### Все аргументы

| Аргумент | Описание |
|---|---|
| `--subnet CIDR` | Сканируемая подсеть (например, `10.0.0.0/24`) |
| `--community STRING` | SNMP community string (по умолчанию: `public`) |
| `--no-gui` | Только CLI: вывод таблицы без GUI |
| `--max-hosts N` | Ограничение числа хостов (защита от зависания) |
| `--load FILE` | Загрузить топологию из JSON |
| `--timeout SEC` | Таймаут ответа хоста (по умолчанию: 1.0) |

---

## Права доступа

| Платформа | Требование |
|---|---|
| **Linux/macOS** | `sudo python net_topology.py ...` (для ARP-скана) |
| **Windows** | Запуск от имени Администратора + установленный Npcap |

Если прав недостаточно, ARP-сканирование пропускается, но ping-скан через nmap всё равно работает.

---

## Работа с GUI

### Управление узлами
- **Перетаскивание**: зажать левую кнопку мыши на узле
- **Правый клик на узле**: редактировать / удалить устройство
- **Правый клик на пустом месте**: добавить новое устройство

### Управление связями
- **Правый клик на связи**: удалить связь
- **Кнопка «🔗 Добавить связь»**: активирует режим — кликните последовательно на два узла

### Цвета и формы узлов

| Тип | Цвет | Форма |
|---|---|---|
| router | 🔴 красный | ромб |
| switch | 🔵 синий | квадрат |
| bridge | 🟣 фиолетовый | шестиугольник |
| firewall | 🟠 оранжевый | треугольник |
| server | 🟢 зелёный | круг |
| endpoint | ⚫ серый | круг |
| unknown | ⬜ светло-серый | круг |

### Сохранение и экспорт
- **Файл → Сохранить (Ctrl+S)**: JSON-файл топологии
- **Файл → Экспорт GraphML**: для Gephi, yEd и других инструментов

---

## Запуск тестов

```bash
pip install pytest
pytest tests/ -v
```

---

## Определение типа устройства

Используется многоуровневая эвристика с весовым голосованием:

1. **SNMP** (вес 10) — `sysDescr` и `sysServices` по RFC 1213
2. **Открытые порты** (вес 5) — 22=SSH, 23=Telnet, 80/443=HTTP, 161=SNMP, 3389=RDP и др.
3. **Ключевые слова** в hostname/sysDescr (вес 4) — Cisco, MikroTik, pfSense, Ubuntu...
4. **OUI производителя** (вес 3) — Cisco=router, Dell=endpoint, Supermicro=server...
5. **TTL** (вес 2) — 64=Linux/server, 128=Windows/endpoint, 255=Cisco/router

Если тип не определён → `unknown`. Пользователь может изменить тип в редакторе.

---

## Платформозависимые особенности

| Функция | Linux | Windows | macOS |
|---|---|---|---|
| ARP-сканирование (Scapy) | ✅ (нужен root) | ✅ (нужен Npcap + Admin) | ✅ (нужен root) |
| nmap ping-скан | ✅ | ✅ | ✅ |
| nmap port-скан | ✅ | ✅ | ✅ |
| SNMP | ✅ | ✅ | ✅ |
| GUI (PyQt5) | ✅ | ✅ | ✅ |

---

## Поддержка нескольких подсетей (доработка)

### Запуск с несколькими подсетями

```bash
# Через пробел
venv/bin/python net_topology.py --subnets 192.168.1.0/24 10.0.0.0/24

# Через запятую
venv/bin/python net_topology.py --subnets 192.168.1.0/24,10.0.0.0/24

# Параллельное сканирование (быстрее на больших сетях)
venv/bin/python net_topology.py --subnets 192.168.1.0/24 10.0.0.0/24 --parallel

# CLI-режим (без GUI) — мультиинтерфейсные помечены *
venv/bin/python net_topology.py --subnets 192.168.1.0/24 10.0.0.0/24 --no-gui
```

### Мультиинтерфейсные устройства

Если одно устройство (например, маршрутизатор) имеет интерфейсы в нескольких подсетях, программа обнаруживает это по совпадению MAC-адреса и объединяет такие узлы автоматически.

**Визуальное отличие в GUI:**
- Золотистая пунктирная двойная рамка вокруг фигуры
- Символ ★ в подписи узла
- В подписи перечислены все IP-адреса и подсети

**Ручная корректировка (правый клик на узел):**
- **«Объединить с другим узлом»** — если автоматика не нашла совпадение MAC (разные физические порты с разными MAC, но одно устройство по hostname/SNMP)
- **«Разделить интерфейс»** — если автоматика ошибочно объединила два разных устройства

### Поддерживаемые форматы MAC для объединения

| Формат | Пример |
|---|---|
| Linux | `aa:bb:cc:dd:ee:ff` |
| Windows | `AA-BB-CC-DD-EE-FF` |
| Cisco | `aabb.ccdd.eeff` |
| Без разделителей | `aabbccddeeff` |

Все форматы приводятся к единому `AA:BB:CC:DD:EE:FF` перед сравнением.

### Межсетевые связи

Мультиинтерфейсные устройства автоматически соединяются с устройствами в тех же подсетях. Межсетевые связи отображаются **красным пунктиром** (в отличие от обычных серых линий).

### CLI-таблица с несколькими подсетями

```
================================================================================
  ОБНАРУЖЕННЫЕ УСТРОЙСТВА
  * = мультиинтерфейсное устройство (несколько IP/подсетей)
================================================================================
*  *  192.168.1.1    AA:BB:CC:DD:EE:01  router       Cisco Systems         gw.local
      ↳ 10.0.0.1 [10.0.0.0/24]
   192.168.1.10   00:AA:BB:CC:DD:EE  endpoint     Apple, Inc.           macbook
   10.0.0.100     00:CC:DD:EE:FF:00  server        Dell Inc.             fileserver
```
