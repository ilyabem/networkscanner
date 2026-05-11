"""
gui.py — графический интерфейс редактора топологии сети (PyQt5).

Функции GUI:
  - Интерактивная схема сети с перетаскиванием узлов
  - Контекстное меню: изменить тип/IP/имя, удалить устройство
  - Добавление нового устройства и связей
  - Сохранение/загрузка топологии (JSON)
  - Экспорт в GraphML
  - Повторный запуск сканирования
"""

from __future__ import annotations

import logging
import math
import sys
from typing import Optional

from PyQt5.QtCore import Qt, QPointF, QRectF, pyqtSignal
from PyQt5.QtGui import (
    QBrush, QColor, QFont, QPainter, QPen, QPolygonF,
)
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsScene,
    QGraphicsTextItem,
    QGraphicsView,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QStatusBar,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from model import Device, NetworkTopology, DEVICE_TYPES, TYPE_COLORS, TYPE_SHAPES

logger = logging.getLogger("gui")

NODE_RADIUS = 28   # радиус узла на canvas (пиксели)
FONT_SIZE = 8      # размер шрифта подписей


# ─── Элемент узла на сцене ──────────────────────────────────────────────────

class NodeItem(QGraphicsItem):
    """
    Визуальное представление устройства на сцене.
    Поддерживает перетаскивание, подсветку при выборе.
    """

    def __init__(self, device: Device, parent=None) -> None:
        super().__init__(parent)
        self.device = device
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        self._hovered = False

        # Устанавливаем начальную позицию из модели
        if device.position:
            self.setPos(device.position[0], device.position[1])

        # Создаём подпись
        self._label = QGraphicsTextItem(self)
        self._label.setFont(QFont("Arial", FONT_SIZE))
        self._update_label()

    def _update_label(self) -> None:
        dev = self.device
        name = dev.hostname or dev.ip
        text = f"{name}\n{dev.device_type}"
        self._label.setPlainText(text)
        # Центрируем подпись под узлом
        lw = self._label.boundingRect().width()
        self._label.setPos(-lw / 2, NODE_RADIUS + 4)

    def boundingRect(self) -> QRectF:
        r = NODE_RADIUS
        return QRectF(-r - 2, -r - 2, (r + 2) * 2, (r + 2) * 2 + 30)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        color = QColor(TYPE_COLORS.get(self.device.device_type, "#bdc3c7"))
        border_color = QColor("#2c3e50") if self.isSelected() else QColor("#7f8c8d")
        border_width = 3 if self.isSelected() else 1.5

        if self._hovered:
            color = color.lighter(130)

        pen = QPen(border_color, border_width)
        painter.setPen(pen)
        painter.setBrush(QBrush(color))

        shape = TYPE_SHAPES.get(self.device.device_type, "circle")
        r = NODE_RADIUS

        if shape == "circle":
            painter.drawEllipse(QRectF(-r, -r, r * 2, r * 2))
        elif shape == "square":
            painter.drawRect(QRectF(-r, -r, r * 2, r * 2))
        elif shape == "diamond":
            poly = QPolygonF([
                QPointF(0, -r),
                QPointF(r, 0),
                QPointF(0, r),
                QPointF(-r, 0),
            ])
            painter.drawPolygon(poly)
        elif shape == "triangle":
            poly = QPolygonF([
                QPointF(0, -r),
                QPointF(r, r),
                QPointF(-r, r),
            ])
            painter.drawPolygon(poly)
        elif shape == "hexagon":
            pts = [
                QPointF(r * math.cos(math.radians(60 * i - 30)),
                        r * math.sin(math.radians(60 * i - 30)))
                for i in range(6)
            ]
            painter.drawPolygon(QPolygonF(pts))
        else:
            painter.drawEllipse(QRectF(-r, -r, r * 2, r * 2))

        # Рисуем IP внутри фигуры
        painter.setPen(QPen(Qt.white if _is_dark(color) else Qt.black))
        painter.setFont(QFont("Arial", 7, QFont.Bold))
        painter.drawText(QRectF(-r, -r, r * 2, r * 2), Qt.AlignCenter, self.device.ip)

    def itemChange(self, change, value):
        """Перехватываем перемещение узла — обновляем модель и связи."""
        if change == QGraphicsItem.ItemPositionHasChanged:
            pos = self.pos()
            self.device.position = (pos.x(), pos.y())
            # Обновляем связи, привязанные к этому узлу
            scene = self.scene()
            if scene and hasattr(scene, "update_edges_for_node"):
                scene.update_edges_for_node(self.device.node_id)
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event) -> None:
        self._hovered = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self._hovered = False
        self.update()
        super().hoverLeaveEvent(event)

    def refresh(self) -> None:
        """Перерисовать узел после изменения данных устройства."""
        self._update_label()
        self.update()


# ─── Элемент связи на сцене ─────────────────────────────────────────────────

class EdgeItem(QGraphicsLineItem):
    """Линия между двумя узлами."""

    def __init__(
        self,
        src_node: NodeItem,
        dst_node: NodeItem,
        label: str = "",
    ) -> None:
        super().__init__()
        self.src_node = src_node
        self.dst_node = dst_node
        self.edge_label = label
        self.setZValue(-1)  # Связи рисуются под узлами
        pen = QPen(QColor("#95a5a6"), 2, Qt.SolidLine)
        self.setPen(pen)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.update_position()

    def update_position(self) -> None:
        """Обновляет линию по текущим позициям узлов."""
        src_pos = self.src_node.pos()
        dst_pos = self.dst_node.pos()
        self.setLine(src_pos.x(), src_pos.y(), dst_pos.x(), dst_pos.y())

    def paint(self, painter: QPainter, option, widget=None) -> None:
        # Связь подсвечивается при выборе
        if self.isSelected():
            pen = QPen(QColor("#e74c3c"), 2.5, Qt.DashLine)
        else:
            pen = QPen(QColor("#7f8c8d"), 1.5, Qt.SolidLine)
        self.setPen(pen)
        super().paint(painter, option, widget)


# ─── Сцена с бизнес-логикой ─────────────────────────────────────────────────

class TopologyScene(QGraphicsScene):
    """
    QGraphicsScene, расширенная для работы с топологией.
    Хранит маппинг node_id → NodeItem и node_id → [EdgeItem].
    """

    topology_changed = pyqtSignal()  # сигнал «топология изменена»

    def __init__(self, topology: NetworkTopology, parent=None) -> None:
        super().__init__(parent)
        self.topology = topology
        self._node_items: dict[str, NodeItem] = {}   # node_id → NodeItem
        self._edge_items: list[EdgeItem] = []

        # Режим добавления связи: ожидаем клика на второй узел
        self._link_mode = False
        self._link_src: Optional[NodeItem] = None

        self._rebuild()

    # ─── Построение сцены из модели ───────────────────────────────────────

    def _rebuild(self) -> None:
        """Полностью перестраивает сцену из модели топологии."""
        self.clear()
        self._node_items.clear()
        self._edge_items.clear()

        # Создаём NodeItem для каждого устройства
        for nid, device in self.topology.devices.items():
            self._add_node_item(device)

        # Создаём EdgeItem для каждой связи
        for src, dst, attrs in self.topology.links:
            self._add_edge_item(src, dst, attrs.get("label", ""))

    def _add_node_item(self, device: Device) -> NodeItem:
        item = NodeItem(device)
        self.addItem(item)
        self._node_items[device.node_id] = item
        return item

    def _add_edge_item(self, src_id: str, dst_id: str, label: str = "") -> Optional[EdgeItem]:
        src_item = self._node_items.get(src_id)
        dst_item = self._node_items.get(dst_id)
        if not src_item or not dst_item:
            return None
        edge = EdgeItem(src_item, dst_item, label)
        self.addItem(edge)
        self._edge_items.append(edge)
        return edge

    def update_edges_for_node(self, node_id: str) -> None:
        """Обновляет все связи, соединённые с данным узлом."""
        for edge in self._edge_items:
            if (edge.src_node.device.node_id == node_id or
                    edge.dst_node.device.node_id == node_id):
                edge.update_position()

    # ─── Добавление устройств / связей ────────────────────────────────────

    def add_device(self, device: Device) -> None:
        self.topology.add_device(device)
        self._add_node_item(device)
        self.topology_changed.emit()

    def add_link_between(self, src_id: str, dst_id: str, label: str = "manual") -> None:
        self.topology.add_link(src_id, dst_id, label)
        self._add_edge_item(src_id, dst_id, label)
        self.topology_changed.emit()

    # ─── Удаление ─────────────────────────────────────────────────────────

    def delete_device(self, node_id: str) -> None:
        """Удалить устройство и все его связи со сцены и из модели."""
        # Удаляем связи
        to_remove = [
            e for e in self._edge_items
            if (e.src_node.device.node_id == node_id or
                e.dst_node.device.node_id == node_id)
        ]
        for edge in to_remove:
            self.removeItem(edge)
            self._edge_items.remove(edge)

        # Удаляем узел
        item = self._node_items.pop(node_id, None)
        if item:
            self.removeItem(item)

        self.topology.remove_device(node_id)
        self.topology_changed.emit()

    def delete_selected_edge(self) -> None:
        """Удалить выбранную связь."""
        for edge in list(self._edge_items):
            if edge.isSelected():
                src_id = edge.src_node.device.node_id
                dst_id = edge.dst_node.device.node_id
                self.topology.remove_link(src_id, dst_id)
                self.removeItem(edge)
                self._edge_items.remove(edge)
        self.topology_changed.emit()

    # ─── Режим добавления связи ───────────────────────────────────────────

    def start_link_mode(self) -> None:
        self._link_mode = True
        self._link_src = None
        logger.debug("Режим добавления связи включён")

    def stop_link_mode(self) -> None:
        self._link_mode = False
        self._link_src = None

    def mousePressEvent(self, event) -> None:
        if self._link_mode and event.button() == Qt.LeftButton:
            items = self.items(event.scenePos())
            node_item = next((i for i in items if isinstance(i, NodeItem)), None)
            if node_item:
                if self._link_src is None:
                    self._link_src = node_item
                    logger.debug("Связь: выбран источник %s", node_item.device.ip)
                else:
                    dst = node_item
                    src = self._link_src
                    if src.device.node_id != dst.device.node_id:
                        self.add_link_between(
                            src.device.node_id,
                            dst.device.node_id,
                            label="manual",
                        )
                    self.stop_link_mode()
            return
        super().mousePressEvent(event)

    # ─── Контекстное меню узла ────────────────────────────────────────────

    def contextMenuEvent(self, event) -> None:
        items = self.items(event.scenePos())
        node_item = next((i for i in items if isinstance(i, NodeItem)), None)
        edge_item = next((i for i in items if isinstance(i, EdgeItem)), None)

        menu = QMenu()

        if node_item:
            dev = node_item.device
            menu.addSection(f"Устройство: {dev.ip}")
            edit_act = menu.addAction("✏️  Редактировать...")
            del_act  = menu.addAction("🗑️  Удалить устройство")
            link_act = menu.addAction("🔗  Добавить связь от этого узла")

            action = menu.exec_(event.screenPos())
            if action == edit_act:
                self._edit_device_dialog(node_item)
            elif action == del_act:
                reply = QMessageBox.question(
                    None, "Подтверждение",
                    f"Удалить устройство {dev.ip}?",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if reply == QMessageBox.Yes:
                    self.delete_device(dev.node_id)
            elif action == link_act:
                self._link_src = node_item
                self.start_link_mode()
                self._link_src = node_item  # восстанавливаем после start_link_mode

        elif edge_item:
            menu.addSection("Связь")
            del_edge_act = menu.addAction("🗑️  Удалить связь")
            action = menu.exec_(event.screenPos())
            if action == del_edge_act:
                edge_item.setSelected(True)
                self.delete_selected_edge()
        else:
            # Клик на пустом месте — добавить устройство
            menu.addSection("Холст")
            add_act = menu.addAction("➕  Добавить устройство здесь")
            action = menu.exec_(event.screenPos())
            if action == add_act:
                pos = event.scenePos()
                self._add_device_dialog(pos)

    def _edit_device_dialog(self, node_item: NodeItem) -> None:
        dev = node_item.device
        dialog = DeviceEditDialog(dev)
        if dialog.exec_() == QDialog.Accepted:
            node_item.refresh()
            self.topology_changed.emit()

    def _add_device_dialog(self, pos: QPointF) -> None:
        dialog = DeviceEditDialog(Device(ip="0.0.0.0"))
        if dialog.exec_() == QDialog.Accepted:
            dev = dialog.device
            dev.position = (pos.x(), pos.y())
            self.add_device(dev)


# ─── Диалог редактирования устройства ───────────────────────────────────────

class DeviceEditDialog(QDialog):
    """Диалог для изменения атрибутов устройства."""

    def __init__(self, device: Device, parent=None) -> None:
        super().__init__(parent)
        self.device = device
        self.setWindowTitle("Редактирование устройства")
        self.setMinimumWidth(320)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QFormLayout(self)

        self.ip_edit = QLineEdit(self.device.ip)
        self.hostname_edit = QLineEdit(self.device.hostname or "")
        self.mac_edit = QLineEdit(self.device.mac or "")

        self.type_combo = QComboBox()
        for t in DEVICE_TYPES:
            self.type_combo.addItem(t)
        idx = DEVICE_TYPES.index(self.device.device_type) if self.device.device_type in DEVICE_TYPES else 0
        self.type_combo.setCurrentIndex(idx)

        self.notes_edit = QLineEdit(self.device.notes)

        layout.addRow("IP-адрес:", self.ip_edit)
        layout.addRow("Имя хоста:", self.hostname_edit)
        layout.addRow("MAC-адрес:", self.mac_edit)
        layout.addRow("Тип устройства:", self.type_combo)
        layout.addRow("Заметки:", self.notes_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._apply)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _apply(self) -> None:
        self.device.ip       = self.ip_edit.text().strip() or self.device.ip
        self.device.hostname = self.hostname_edit.text().strip() or None
        self.device.mac      = self.mac_edit.text().strip() or None
        self.device.device_type = self.type_combo.currentText()
        self.device.notes    = self.notes_edit.text().strip()
        self.accept()


# ─── Главное окно приложения ────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self, topology: NetworkTopology) -> None:
        super().__init__()
        self.topology = topology
        self.setWindowTitle("Редактор топологии сети")
        self.resize(1100, 750)
        self._current_file: Optional[str] = None
        self._modified = False

        self._build_ui()
        self._build_menu()
        self._build_toolbar()
        self._refresh_scene()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        # ── Панель инструментов (вверху) ──────────────────────────────────
        ctrl_bar = QWidget()
        ctrl_layout = QHBoxLayout(ctrl_bar)
        ctrl_layout.setContentsMargins(6, 4, 6, 4)

        self.subnet_edit = QLineEdit()
        self.subnet_edit.setPlaceholderText("192.168.1.0/24")
        self.subnet_edit.setMaximumWidth(200)
        self.community_edit = QLineEdit("public")
        self.community_edit.setMaximumWidth(100)
        self.scan_btn = QPushButton("▶ Сканировать")
        self.scan_btn.clicked.connect(self._on_scan)

        ctrl_layout.addWidget(QLabel("Подсеть:"))
        ctrl_layout.addWidget(self.subnet_edit)
        ctrl_layout.addWidget(QLabel("Community:"))
        ctrl_layout.addWidget(self.community_edit)
        ctrl_layout.addWidget(self.scan_btn)
        ctrl_layout.addStretch()

        self.add_link_btn = QPushButton("🔗 Добавить связь")
        self.add_link_btn.setCheckable(True)
        self.add_link_btn.clicked.connect(self._toggle_link_mode)
        ctrl_layout.addWidget(self.add_link_btn)

        layout.addWidget(ctrl_bar)

        # ── Граф ─────────────────────────────────────────────────────────
        self.view = QGraphicsView()
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setDragMode(QGraphicsView.RubberBandDrag)
        self.view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.view.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        layout.addWidget(self.view)

        # Статусная строка
        self.statusBar().showMessage("Готово")

    def _build_menu(self) -> None:
        menu_bar = self.menuBar()

        # Файл
        file_menu = menu_bar.addMenu("Файл")
        file_menu.addAction("Открыть топологию...", self._open_file, "Ctrl+O")
        file_menu.addAction("Сохранить",            self._save_file, "Ctrl+S")
        file_menu.addAction("Сохранить как...",     self._save_as,   "Ctrl+Shift+S")
        file_menu.addSeparator()
        file_menu.addAction("Экспорт GraphML...",   self._export_graphml)
        file_menu.addSeparator()
        file_menu.addAction("Выход", self.close)

        # Правка
        edit_menu = menu_bar.addMenu("Правка")
        edit_menu.addAction("Добавить устройство...", self._add_device_dialog)
        edit_menu.addAction("Удалить выбранную связь", self._delete_selected_edge, "Delete")

        # Вид
        view_menu = menu_bar.addMenu("Вид")
        view_menu.addAction("Сбросить масштаб", self._reset_zoom, "Ctrl+0")
        view_menu.addAction("Вписать в экран",  self._fit_view,   "Ctrl+F")

    def _build_toolbar(self) -> None:
        tb = self.addToolBar("Основное")
        tb.addAction("Открыть",    self._open_file)
        tb.addAction("Сохранить",  self._save_file)
        tb.addSeparator()
        tb.addAction("Сканировать", self._on_scan)
        tb.addAction("Вписать",    self._fit_view)

    # ─── Сцена ────────────────────────────────────────────────────────────

    def _refresh_scene(self) -> None:
        """Создаёт/пересоздаёт сцену из текущей топологии."""
        scene = TopologyScene(self.topology)
        scene.topology_changed.connect(self._on_topology_changed)
        self.view.setScene(scene)
        self._scene = scene
        count = len(self.topology.devices)
        self.statusBar().showMessage(f"Устройств: {count} | Связей: {len(self.topology.links)}")

    def _on_topology_changed(self) -> None:
        self._modified = True
        count = len(self.topology.devices)
        title = f"Редактор топологии сети — {self._current_file or 'без имени'}{'*' if self._modified else ''}"
        self.setWindowTitle(title)
        self.statusBar().showMessage(f"Устройств: {count} | Связей: {len(self.topology.links)}")

    # ─── Сканирование ─────────────────────────────────────────────────────

    def _on_scan(self) -> None:
        subnet = self.subnet_edit.text().strip()
        if not subnet:
            QMessageBox.warning(self, "Предупреждение", "Введите подсеть (CIDR)")
            return

        # Импортируем здесь, чтобы не создавать циклических зависимостей при тестировании
        from scanner import NetworkScanner
        from analyzer import DeviceAnalyzer

        self.scan_btn.setEnabled(False)
        self.statusBar().showMessage("Сканирование...")

        try:
            scanner = NetworkScanner(
                subnet=subnet,
                snmp_community=self.community_edit.text().strip() or "public",
            )
            hosts = scanner.scan()
            analyzer = DeviceAnalyzer(snmp_community=self.community_edit.text().strip())
            for host in hosts:
                analyzer.enrich(host)

            # Пересобираем топологию
            self.topology = NetworkTopology()
            self.topology.build_from_hosts(hosts, scanner.get_arp_table())
            self._refresh_scene()
            self.statusBar().showMessage(f"Сканирование завершено. Найдено: {len(hosts)} хостов")
        except PermissionError:
            QMessageBox.critical(
                self, "Ошибка прав",
                "Недостаточно прав для ARP-сканирования.\n"
                "Запустите программу от имени администратора (Windows) или root (Linux)."
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка сканирования", str(exc))
        finally:
            self.scan_btn.setEnabled(True)

    # ─── Добавление устройства вручную ────────────────────────────────────

    def _add_device_dialog(self) -> None:
        dev = Device(ip="192.168.1.1")
        dialog = DeviceEditDialog(dev, self)
        if dialog.exec_() == QDialog.Accepted:
            dev.position = (400, 300)
            self._scene.add_device(dev)

    def _delete_selected_edge(self) -> None:
        self._scene.delete_selected_edge()

    # ─── Режим добавления связи ───────────────────────────────────────────

    def _toggle_link_mode(self, checked: bool) -> None:
        if checked:
            self._scene.start_link_mode()
            self.statusBar().showMessage(
                "Режим связи: кликните на первый узел, затем на второй"
            )
        else:
            self._scene.stop_link_mode()
            self.statusBar().showMessage("Готово")

    # ─── Файловые операции ────────────────────────────────────────────────

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Открыть топологию", "", "JSON (*.json);;Все файлы (*)"
        )
        if path:
            self.topology.load_json(path)
            self._current_file = path
            self._modified = False
            self._refresh_scene()

    def _save_file(self) -> None:
        if not self._current_file:
            self._save_as()
            return
        self.topology.save_json(self._current_file)
        self._modified = False
        self.setWindowTitle(f"Редактор топологии сети — {self._current_file}")

    def _save_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить топологию", "topology.json", "JSON (*.json);;Все файлы (*)"
        )
        if path:
            self._current_file = path
            self._save_file()

    def _export_graphml(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт GraphML", "topology.graphml", "GraphML (*.graphml)"
        )
        if path:
            self.topology.export_graphml(path)
            self.statusBar().showMessage(f"Экспортировано: {path}")

    # ─── Масштаб / вид ────────────────────────────────────────────────────

    def _fit_view(self) -> None:
        self.view.fitInView(self._scene.sceneRect(), Qt.KeepAspectRatio)

    def _reset_zoom(self) -> None:
        self.view.resetTransform()

    def wheelEvent(self, event) -> None:
        """Масштабирование колёсиком мыши."""
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.view.scale(factor, factor)

    def closeEvent(self, event) -> None:
        if self._modified:
            reply = QMessageBox.question(
                self, "Несохранённые изменения",
                "Топология была изменена. Сохранить перед выходом?",
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
            )
            if reply == QMessageBox.Save:
                self._save_file()
            elif reply == QMessageBox.Cancel:
                event.ignore()
                return
        event.accept()


# ─── Вспомогательная функция ────────────────────────────────────────────────

def _is_dark(color: QColor) -> bool:
    """Проверяет, является ли цвет тёмным (для выбора цвета текста)."""
    r, g, b = color.red(), color.green(), color.blue()
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    return luminance < 128


# ─── Точка входа в GUI ──────────────────────────────────────────────────────

def run_gui(topology: NetworkTopology) -> None:
    """Запускает Qt-приложение с редактором топологии."""
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Net Topology Editor")
    app.setStyle("Fusion")

    window = MainWindow(topology)
    window.show()

    sys.exit(app.exec_())
