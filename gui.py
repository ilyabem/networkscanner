"""
gui.py — графический интерфейс редактора топологии сети (PyQt5).

ДОРАБОТКА (multi-subnet / multi-homed):
  - Мультиинтерфейсные узлы рисуются с двойной рамкой и значком ★.
  - Контекстное меню узла: «Разделить интерфейс», «Объединить с...».
  - Диалог DeviceEditDialog показывает все интерфейсы устройства.
  - Диалог MergeDialog: выбор узла для объединения.
  - Диалог SplitDialog: выбор IP для отщепления.
  - Панель сканирования поддерживает поле «Подсети» (несколько через запятую).
  - Поддержка параллельного сканирования через QThread.
"""

from __future__ import annotations

import logging
import math
import sys
from typing import Optional

from PyQt5.QtCore import Qt, QPointF, QRectF, QThread, pyqtSignal
from PyQt5.QtGui import (
    QBrush, QColor, QFont, QPainter, QPen, QPolygonF,
)
from PyQt5.QtWidgets import (
    QAction, QApplication, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QGraphicsEllipseItem, QGraphicsItem,
    QGraphicsLineItem, QGraphicsScene, QGraphicsTextItem, QGraphicsView,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMenu, QMessageBox, QPushButton, QSplitter,
    QVBoxLayout, QWidget, QCheckBox, QTextEdit,
)

from model import Device, Interface, NetworkTopology, DEVICE_TYPES, TYPE_COLORS, TYPE_SHAPES

logger = logging.getLogger("gui")

NODE_RADIUS = 28
FONT_SIZE   = 8

# Цвет двойной рамки для мультиинтерфейсных узлов
MULTIHOMED_BORDER_COLOR = "#f39c12"   # золотистый
MULTIHOMED_BORDER_WIDTH = 4


# ─── Фоновый поток сканирования ──────────────────────────────────────────────

class ScanWorker(QThread):
    """
    Запускает сканирование в отдельном потоке, чтобы не блокировать GUI.
    Сигнал finished передаёт готовую топологию обратно в главный поток.
    """
    finished = pyqtSignal(object)   # NetworkTopology
    error    = pyqtSignal(str)

    def __init__(self, subnets: list[str], community: str, parallel: bool = False) -> None:
        super().__init__()
        self.subnets   = subnets
        self.community = community
        self.parallel  = parallel

    def run(self) -> None:
        try:
            from net_topology import scan_subnet
            from concurrent.futures import ThreadPoolExecutor, as_completed

            subnet_results = []
            if self.parallel and len(self.subnets) > 1:
                with ThreadPoolExecutor(max_workers=len(self.subnets)) as ex:
                    futures = {
                        ex.submit(scan_subnet, s, self.community, 1.0, 254): s
                        for s in self.subnets
                    }
                    for fut in as_completed(futures):
                        try:
                            subnet_results.append(fut.result())
                        except Exception as exc:
                            logger.warning("Ошибка сканирования %s: %s", futures[fut], exc)
            else:
                for subnet in self.subnets:
                    try:
                        subnet_results.append(scan_subnet(subnet, self.community, 1.0, 254))
                    except Exception as exc:
                        logger.warning("Ошибка сканирования %s: %s", subnet, exc)

            topology = NetworkTopology()
            if len(subnet_results) == 1:
                s, hosts, arp = subnet_results[0]
                topology.build_from_hosts(hosts, arp, subnet=s)
            elif len(subnet_results) > 1:
                topology.build_from_multi_subnet(subnet_results)

            self.finished.emit(topology)
        except Exception as exc:
            self.error.emit(str(exc))


# ─── Узел на сцене ───────────────────────────────────────────────────────────

class NodeItem(QGraphicsItem):
    """
    Визуальное представление устройства.

    ДОРАБОТКА: мультиинтерфейсные узлы рисуются с двойной золотистой рамкой
    и символом ★ в верхнем левом углу фигуры.
    """

    def __init__(self, device: Device, parent=None) -> None:
        super().__init__(parent)
        self.device = device
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        self._hovered = False

        if device.position:
            self.setPos(device.position[0], device.position[1])

        self._label = QGraphicsTextItem(self)
        self._label.setFont(QFont("Arial", FONT_SIZE))
        self._update_label()

    def _update_label(self) -> None:
        dev = self.device
        if dev.is_multihomed:
            # Показываем все IP
            name = dev.hostname or dev.ip
            text = f"★ {name}\n[{dev.device_type}]\n{dev.interfaces_label()}"
        else:
            name = dev.hostname or dev.ip
            text = f"{name}\n[{dev.device_type}]"
        self._label.setPlainText(text)
        lw = self._label.boundingRect().width()
        self._label.setPos(-lw / 2, NODE_RADIUS + 4)

    def boundingRect(self) -> QRectF:
        r = NODE_RADIUS + (MULTIHOMED_BORDER_WIDTH if self.device.is_multihomed else 0)
        return QRectF(-r - 4, -r - 4, (r + 4) * 2, (r + 4) * 2 + 50)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        color        = QColor(TYPE_COLORS.get(self.device.device_type, "#bdc3c7"))
        border_color = QColor("#2c3e50") if self.isSelected() else QColor("#7f8c8d")
        border_width = 3 if self.isSelected() else 1.5

        if self._hovered:
            color = color.lighter(130)

        r     = NODE_RADIUS
        shape = TYPE_SHAPES.get(self.device.device_type, "circle")

        # ── Внешняя двойная рамка для мультиинтерфейсных ─────────────────────
        if self.device.is_multihomed:
            outer_pen = QPen(QColor(MULTIHOMED_BORDER_COLOR), MULTIHOMED_BORDER_WIDTH)
            outer_pen.setStyle(Qt.DashLine)
            painter.setPen(outer_pen)
            painter.setBrush(Qt.NoBrush)
            ro = r + MULTIHOMED_BORDER_WIDTH + 2
            self._draw_shape(painter, shape, ro)

        # ── Основная фигура ───────────────────────────────────────────────────
        painter.setPen(QPen(border_color, border_width))
        painter.setBrush(QBrush(color))
        self._draw_shape(painter, shape, r)

        # ── IP внутри фигуры ──────────────────────────────────────────────────
        painter.setPen(QPen(Qt.white if _is_dark(color) else Qt.black))
        painter.setFont(QFont("Arial", 7, QFont.Bold))
        painter.drawText(QRectF(-r, -r, r * 2, r * 2), Qt.AlignCenter, self.device.ip)

    @staticmethod
    def _draw_shape(painter: QPainter, shape: str, r: float) -> None:
        """Рисует фигуру заданного типа радиуса r."""
        if shape == "circle":
            painter.drawEllipse(QRectF(-r, -r, r * 2, r * 2))
        elif shape == "square":
            painter.drawRect(QRectF(-r, -r, r * 2, r * 2))
        elif shape == "diamond":
            painter.drawPolygon(QPolygonF([
                QPointF(0, -r), QPointF(r, 0), QPointF(0, r), QPointF(-r, 0),
            ]))
        elif shape == "triangle":
            painter.drawPolygon(QPolygonF([
                QPointF(0, -r), QPointF(r, r), QPointF(-r, r),
            ]))
        elif shape == "hexagon":
            pts = [
                QPointF(r * math.cos(math.radians(60 * i - 30)),
                        r * math.sin(math.radians(60 * i - 30)))
                for i in range(6)
            ]
            painter.drawPolygon(QPolygonF(pts))
        else:
            painter.drawEllipse(QRectF(-r, -r, r * 2, r * 2))

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            pos = self.pos()
            self.device.position = (pos.x(), pos.y())
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
        self._update_label()
        self.prepareGeometryChange()
        self.update()


# ─── Связь на сцене ──────────────────────────────────────────────────────────

class EdgeItem(QGraphicsLineItem):
    def __init__(self, src_node: NodeItem, dst_node: NodeItem, label: str = "") -> None:
        super().__init__()
        self.src_node   = src_node
        self.dst_node   = dst_node
        self.edge_label = label
        self.setZValue(-1)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.update_position()

    def update_position(self) -> None:
        s = self.src_node.pos()
        d = self.dst_node.pos()
        self.setLine(s.x(), s.y(), d.x(), d.y())

    def paint(self, painter, option, widget=None) -> None:
        # Межсетевые связи — пунктир другого цвета
        if self.edge_label == "inter-subnet":
            pen = QPen(QColor("#e74c3c"), 2, Qt.DashDotLine)
        elif self.isSelected():
            pen = QPen(QColor("#e74c3c"), 2.5, Qt.DashLine)
        else:
            pen = QPen(QColor("#7f8c8d"), 1.5, Qt.SolidLine)
        self.setPen(pen)
        super().paint(painter, option, widget)


# ─── Сцена ───────────────────────────────────────────────────────────────────

class TopologyScene(QGraphicsScene):
    topology_changed = pyqtSignal()

    def __init__(self, topology: NetworkTopology, parent=None) -> None:
        super().__init__(parent)
        self.topology     = topology
        self._node_items: dict[str, NodeItem] = {}
        self._edge_items: list[EdgeItem]       = []
        self._link_mode  = False
        self._link_src: Optional[NodeItem] = None
        self._rebuild()

    def _rebuild(self) -> None:
        self.clear()
        self._node_items.clear()
        self._edge_items.clear()
        for dev in self.topology.devices.values():
            self._add_node_item(dev)
        for src, dst, attrs in self.topology.links:
            self._add_edge_item(src, dst, attrs.get("label", ""))

    def _add_node_item(self, device: Device) -> NodeItem:
        item = NodeItem(device)
        self.addItem(item)
        self._node_items[device.node_id] = item
        return item

    def _add_edge_item(self, src_id: str, dst_id: str, label: str = "") -> Optional[EdgeItem]:
        src = self._node_items.get(src_id)
        dst = self._node_items.get(dst_id)
        if not src or not dst:
            return None
        edge = EdgeItem(src, dst, label)
        self.addItem(edge)
        self._edge_items.append(edge)
        return edge

    def update_edges_for_node(self, node_id: str) -> None:
        for edge in self._edge_items:
            if (edge.src_node.device.node_id == node_id or
                    edge.dst_node.device.node_id == node_id):
                edge.update_position()

    # ── Добавление ───────────────────────────────────────────────────────────

    def add_device(self, device: Device) -> None:
        self.topology.add_device(device)
        self._add_node_item(device)
        self.topology_changed.emit()

    def add_link_between(self, src_id: str, dst_id: str, label: str = "manual") -> None:
        self.topology.add_link(src_id, dst_id, label)
        self._add_edge_item(src_id, dst_id, label)
        self.topology_changed.emit()

    # ── Удаление ─────────────────────────────────────────────────────────────

    def delete_device(self, node_id: str) -> None:
        to_remove = [
            e for e in self._edge_items
            if e.src_node.device.node_id == node_id or
               e.dst_node.device.node_id == node_id
        ]
        for edge in to_remove:
            self.removeItem(edge)
            self._edge_items.remove(edge)
        item = self._node_items.pop(node_id, None)
        if item:
            self.removeItem(item)
        self.topology.remove_device(node_id)
        self.topology_changed.emit()

    def delete_selected_edge(self) -> None:
        for edge in list(self._edge_items):
            if edge.isSelected():
                self.topology.remove_link(
                    edge.src_node.device.node_id,
                    edge.dst_node.device.node_id,
                )
                self.removeItem(edge)
                self._edge_items.remove(edge)
        self.topology_changed.emit()

    # ── Объединение / разделение ─────────────────────────────────────────────

    def merge_nodes(self, primary_id: str, secondary_id: str) -> None:
        """Объединяет два узла: secondary → primary."""
        if self.topology.merge_devices(primary_id, secondary_id):
            # Удаляем visual secondary
            to_remove = [
                e for e in self._edge_items
                if e.src_node.device.node_id == secondary_id or
                   e.dst_node.device.node_id == secondary_id
            ]
            for edge in to_remove:
                self.removeItem(edge)
                self._edge_items.remove(edge)
            item = self._node_items.pop(secondary_id, None)
            if item:
                self.removeItem(item)
            # Обновляем внешний вид primary
            primary_item = self._node_items.get(primary_id)
            if primary_item:
                primary_item.refresh()
            # Перестраиваем рёбра из модели
            self._rebuild_edges()
            self.topology_changed.emit()

    def split_node(self, node_id: str, split_ip: str) -> None:
        """Отделяет IP в новый узел."""
        new_id = self.topology.split_device(node_id, split_ip)
        if new_id:
            new_dev = self.topology.devices[new_id]
            new_dev.position = (
                self._node_items[node_id].pos().x() + 100,
                self._node_items[node_id].pos().y() + 100,
            )
            self._add_node_item(new_dev)
            # Обновляем основной узел
            item = self._node_items.get(node_id)
            if item:
                item.refresh()
            self.topology_changed.emit()

    def _rebuild_edges(self) -> None:
        """Перестраивает только рёбра (без пересоздания узлов)."""
        for edge in self._edge_items:
            self.removeItem(edge)
        self._edge_items.clear()
        for src, dst, attrs in self.topology.links:
            self._add_edge_item(src, dst, attrs.get("label", ""))

    # ── Режим добавления связи ────────────────────────────────────────────────

    def start_link_mode(self) -> None:
        self._link_mode = True
        self._link_src  = None

    def stop_link_mode(self) -> None:
        self._link_mode = False
        self._link_src  = None

    def mousePressEvent(self, event) -> None:
        if self._link_mode and event.button() == Qt.LeftButton:
            items = self.items(event.scenePos())
            node  = next((i for i in items if isinstance(i, NodeItem)), None)
            if node:
                if self._link_src is None:
                    self._link_src = node
                else:
                    src = self._link_src
                    if src.device.node_id != node.device.node_id:
                        self.add_link_between(src.device.node_id, node.device.node_id)
                    self.stop_link_mode()
            return
        super().mousePressEvent(event)

    # ── Контекстное меню ─────────────────────────────────────────────────────

    def contextMenuEvent(self, event) -> None:
        items     = self.items(event.scenePos())
        node_item = next((i for i in items if isinstance(i, NodeItem)), None)
        edge_item = next((i for i in items if isinstance(i, EdgeItem)), None)

        menu = QMenu()

        if node_item:
            dev = node_item.device
            menu.addSection(f"{'★ ' if dev.is_multihomed else ''}{dev.ip}")
            edit_act  = menu.addAction("✏️  Редактировать...")
            del_act   = menu.addAction("🗑️  Удалить устройство")
            link_act  = menu.addAction("🔗  Добавить связь")
            menu.addSeparator()
            merge_act = menu.addAction("🔀  Объединить с другим узлом...")
            split_act = menu.addAction("✂️  Разделить интерфейс...")
            split_act.setEnabled(dev.is_multihomed)

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
                self._link_src = node_item
            elif action == merge_act:
                self._merge_dialog(node_item)
            elif action == split_act:
                self._split_dialog(node_item)

        elif edge_item:
            menu.addSection("Связь")
            del_edge = menu.addAction("🗑️  Удалить связь")
            action   = menu.exec_(event.screenPos())
            if action == del_edge:
                edge_item.setSelected(True)
                self.delete_selected_edge()

        else:
            menu.addSection("Холст")
            add_act = menu.addAction("➕  Добавить устройство здесь")
            action  = menu.exec_(event.screenPos())
            if action == add_act:
                self._add_device_dialog(event.scenePos())

    def _edit_device_dialog(self, node_item: NodeItem) -> None:
        dialog = DeviceEditDialog(node_item.device, self.topology)
        if dialog.exec_() == QDialog.Accepted:
            node_item.refresh()
            self.topology_changed.emit()

    def _add_device_dialog(self, pos: QPointF) -> None:
        dev = Device(ip="0.0.0.0")
        dialog = DeviceEditDialog(dev, self.topology)
        if dialog.exec_() == QDialog.Accepted:
            dev.position = (pos.x(), pos.y())
            self.add_device(dev)

    def _merge_dialog(self, node_item: NodeItem) -> None:
        """Диалог выбора узла для объединения."""
        dialog = MergeDialog(node_item.device, self.topology, parent=None)
        if dialog.exec_() == QDialog.Accepted and dialog.selected_id:
            self.merge_nodes(node_item.device.node_id, dialog.selected_id)

    def _split_dialog(self, node_item: NodeItem) -> None:
        """Диалог выбора IP для отщепления."""
        dialog = SplitDialog(node_item.device, parent=None)
        if dialog.exec_() == QDialog.Accepted and dialog.selected_ip:
            self.split_node(node_item.device.node_id, dialog.selected_ip)


# ─── Диалог редактирования устройства ────────────────────────────────────────

class DeviceEditDialog(QDialog):
    """
    Диалог редактирования атрибутов устройства.
    ДОРАБОТКА: отображает все интерфейсы мультиинтерфейсного устройства.
    """

    def __init__(self, device: Device, topology: NetworkTopology, parent=None) -> None:
        super().__init__(parent)
        self.device   = device
        self.topology = topology
        self.setWindowTitle("Редактирование устройства")
        self.setMinimumWidth(380)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QFormLayout(self)

        self.ip_edit       = QLineEdit(self.device.ip)
        self.hostname_edit = QLineEdit(self.device.hostname or "")
        self.mac_edit      = QLineEdit(self.device.mac or "")
        self.subnet_edit   = QLineEdit(self.device.subnet or "")
        self.notes_edit    = QLineEdit(self.device.notes)

        self.type_combo = QComboBox()
        for t in DEVICE_TYPES:
            self.type_combo.addItem(t)
        idx = DEVICE_TYPES.index(self.device.device_type) \
            if self.device.device_type in DEVICE_TYPES else 0
        self.type_combo.setCurrentIndex(idx)

        layout.addRow("IP-адрес:",        self.ip_edit)
        layout.addRow("Имя хоста:",       self.hostname_edit)
        layout.addRow("MAC-адрес:",       self.mac_edit)
        layout.addRow("Подсеть (CIDR):",  self.subnet_edit)
        layout.addRow("Тип устройства:",  self.type_combo)
        layout.addRow("Заметки:",         self.notes_edit)

        # Список интерфейсов (только для мультиинтерфейсных)
        if self.device.is_multihomed or len(self.device.interfaces) > 1:
            layout.addRow(QLabel("── Интерфейсы ──"))
            iface_text = QTextEdit()
            iface_text.setReadOnly(True)
            iface_text.setMaximumHeight(100)
            iface_text.setPlainText(self.device.interfaces_label())
            layout.addRow("Все IP:", iface_text)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._apply)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _apply(self) -> None:
        self.device.ip          = self.ip_edit.text().strip() or self.device.ip
        self.device.hostname    = self.hostname_edit.text().strip() or None
        self.device.mac         = self.mac_edit.text().strip() or None
        self.device.subnet      = self.subnet_edit.text().strip()
        self.device.device_type = self.type_combo.currentText()
        self.device.notes       = self.notes_edit.text().strip()
        self.accept()


# ─── Диалог объединения узлов ─────────────────────────────────────────────────

class MergeDialog(QDialog):
    """Выбор узла для объединения с текущим."""

    def __init__(self, device: Device, topology: NetworkTopology, parent=None) -> None:
        super().__init__(parent)
        self.device      = device
        self.topology    = topology
        self.selected_id: Optional[str] = None
        self.setWindowTitle(f"Объединить {device.ip} с...")
        self.setMinimumWidth(320)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Выберите узел для объединения:"))

        self.list_widget = QListWidget()
        for nid, dev in self.topology.devices.items():
            if nid == self.device.node_id:
                continue
            item = QListWidgetItem(f"{dev.ip}  [{dev.device_type}]  {dev.hostname or ''}")
            item.setData(Qt.UserRole, nid)
            self.list_widget.addItem(item)
        layout.addWidget(self.list_widget)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._apply)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _apply(self) -> None:
        item = self.list_widget.currentItem()
        if item:
            self.selected_id = item.data(Qt.UserRole)
            self.accept()


# ─── Диалог разделения узла ───────────────────────────────────────────────────

class SplitDialog(QDialog):
    """Выбор IP для отщепления из мультиинтерфейсного узла."""

    def __init__(self, device: Device, parent=None) -> None:
        super().__init__(parent)
        self.device      = device
        self.selected_ip: Optional[str] = None
        self.setWindowTitle(f"Разделить узел {device.ip}")
        self.setMinimumWidth(300)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Выберите IP для выделения в отдельный узел:"))

        self.list_widget = QListWidget()
        for iface in self.device.interfaces:
            if iface.ip == self.device.ip:
                continue   # основной IP оставляем
            label = f"{iface.ip}"
            if iface.subnet:
                label += f"  [{iface.subnet}]"
            if iface.iface_name:
                label += f"  ({iface.iface_name})"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, iface.ip)
            self.list_widget.addItem(item)
        layout.addWidget(self.list_widget)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._apply)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _apply(self) -> None:
        item = self.list_widget.currentItem()
        if item:
            self.selected_ip = item.data(Qt.UserRole)
            self.accept()


# ─── Главное окно ─────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self, topology: NetworkTopology) -> None:
        super().__init__()
        self.topology       = topology
        self._current_file: Optional[str] = None
        self._modified      = False
        self._scan_worker: Optional[ScanWorker] = None

        self.setWindowTitle("Редактор топологии сети")
        self.resize(1200, 800)
        self._build_ui()
        self._build_menu()
        self._refresh_scene()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout  = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        # ── Панель управления сканированием ─────────────────────────────────
        ctrl = QWidget()
        ctrl_layout = QHBoxLayout(ctrl)
        ctrl_layout.setContentsMargins(6, 4, 6, 4)

        self.subnets_edit = QLineEdit()
        self.subnets_edit.setPlaceholderText("192.168.1.0/24, 10.0.0.0/24")
        self.subnets_edit.setMinimumWidth(240)

        self.community_edit = QLineEdit("public")
        self.community_edit.setMaximumWidth(100)

        self.parallel_cb = QCheckBox("Параллельно")
        self.parallel_cb.setToolTip("Сканировать подсети одновременно")

        self.scan_btn = QPushButton("▶ Сканировать")
        self.scan_btn.clicked.connect(self._on_scan)

        self.add_link_btn = QPushButton("🔗 Добавить связь")
        self.add_link_btn.setCheckable(True)
        self.add_link_btn.clicked.connect(self._toggle_link_mode)

        ctrl_layout.addWidget(QLabel("Подсети:"))
        ctrl_layout.addWidget(self.subnets_edit)
        ctrl_layout.addWidget(QLabel("Community:"))
        ctrl_layout.addWidget(self.community_edit)
        ctrl_layout.addWidget(self.parallel_cb)
        ctrl_layout.addWidget(self.scan_btn)
        ctrl_layout.addStretch()
        ctrl_layout.addWidget(self.add_link_btn)
        layout.addWidget(ctrl)

        # ── Граф ────────────────────────────────────────────────────────────
        self.view = QGraphicsView()
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setDragMode(QGraphicsView.RubberBandDrag)
        self.view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        layout.addWidget(self.view)

        # ── Статусная строка ─────────────────────────────────────────────────
        self.statusBar().showMessage("Готово")

    def _build_menu(self) -> None:
        mb = self.menuBar()

        fm = mb.addMenu("Файл")
        fm.addAction("Открыть...",        self._open_file,     "Ctrl+O")
        fm.addAction("Сохранить",         self._save_file,     "Ctrl+S")
        fm.addAction("Сохранить как...",  self._save_as,       "Ctrl+Shift+S")
        fm.addSeparator()
        fm.addAction("Экспорт GraphML...", self._export_graphml)
        fm.addSeparator()
        fm.addAction("Выход", self.close)

        em = mb.addMenu("Правка")
        em.addAction("Добавить устройство...",    self._add_device_dialog)
        em.addAction("Удалить выбранную связь",   self._delete_selected_edge, "Delete")
        em.addSeparator()
        em.addAction("Объединить по MAC (авто)", self._auto_merge_by_mac)

        vm = mb.addMenu("Вид")
        vm.addAction("Вписать в экран", self._fit_view,   "Ctrl+F")
        vm.addAction("Сбросить масштаб", self._reset_zoom, "Ctrl+0")

    # ── Сцена ─────────────────────────────────────────────────────────────────

    def _refresh_scene(self) -> None:
        scene = TopologyScene(self.topology)
        scene.topology_changed.connect(self._on_topology_changed)
        self.view.setScene(scene)
        self._scene = scene
        self._update_status()

    def _on_topology_changed(self) -> None:
        self._modified = True
        self._update_status()
        self.setWindowTitle(
            f"Редактор топологии — "
            f"{self._current_file or 'без имени'}"
            f"{'*' if self._modified else ''}"
        )

    def _update_status(self) -> None:
        multi = sum(1 for d in self.topology.devices.values() if d.is_multihomed)
        self.statusBar().showMessage(
            f"Устройств: {len(self.topology.devices)} "
            f"(мультиинтерфейсных: {multi}) | "
            f"Связей: {len(self.topology.links)}"
        )

    # ── Сканирование ──────────────────────────────────────────────────────────

    def _on_scan(self) -> None:
        raw = self.subnets_edit.text().strip()
        if not raw:
            QMessageBox.warning(self, "Предупреждение",
                                "Введите подсети (через запятую или пробел)")
            return

        # Разбираем подсети
        subnets = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
        if not subnets:
            return

        self.scan_btn.setEnabled(False)
        self.statusBar().showMessage(
            f"Сканирование {len(subnets)} подсет(и/ей)..."
        )

        # Запускаем фоновый поток
        self._scan_worker = ScanWorker(
            subnets   = subnets,
            community = self.community_edit.text().strip() or "public",
            parallel  = self.parallel_cb.isChecked(),
        )
        self._scan_worker.finished.connect(self._on_scan_done)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.start()

    def _on_scan_done(self, topology: NetworkTopology) -> None:
        self.topology = topology
        self._refresh_scene()
        self.scan_btn.setEnabled(True)
        multi = sum(1 for d in topology.devices.values() if d.is_multihomed)
        self.statusBar().showMessage(
            f"Готово. Найдено: {len(topology.devices)} устройств, "
            f"из них мультиинтерфейсных: {multi}"
        )

    def _on_scan_error(self, msg: str) -> None:
        self.scan_btn.setEnabled(True)
        QMessageBox.critical(self, "Ошибка сканирования", msg)

    # ── Правка ────────────────────────────────────────────────────────────────

    def _add_device_dialog(self) -> None:
        dev = Device(ip="0.0.0.0")
        dialog = DeviceEditDialog(dev, self.topology, self)
        if dialog.exec_() == QDialog.Accepted:
            dev.position = (400, 300)
            self._scene.add_device(dev)

    def _delete_selected_edge(self) -> None:
        self._scene.delete_selected_edge()

    def _auto_merge_by_mac(self) -> None:
        """Повторный запуск автоматического объединения по MAC."""
        count = self.topology.merge_by_mac()
        self._refresh_scene()
        QMessageBox.information(
            self, "Объединение по MAC",
            f"Объединено групп дублей: {count}"
        )

    def _toggle_link_mode(self, checked: bool) -> None:
        if checked:
            self._scene.start_link_mode()
            self.statusBar().showMessage(
                "Режим связи: кликните на первый узел, затем на второй"
            )
        else:
            self._scene.stop_link_mode()
            self._update_status()

    # ── Файлы ─────────────────────────────────────────────────────────────────

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Открыть топологию", "", "JSON (*.json);;Все файлы (*)"
        )
        if path:
            self.topology.load_json(path)
            self._current_file = path
            self._modified     = False
            self._refresh_scene()

    def _save_file(self) -> None:
        if not self._current_file:
            self._save_as()
            return
        self.topology.save_json(self._current_file)
        self._modified = False
        self.setWindowTitle(f"Редактор топологии — {self._current_file}")

    def _save_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить как", "topology.json", "JSON (*.json)"
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

    # ── Вид ───────────────────────────────────────────────────────────────────

    def _fit_view(self) -> None:
        self.view.fitInView(self._scene.sceneRect(), Qt.KeepAspectRatio)

    def _reset_zoom(self) -> None:
        self.view.resetTransform()

    def wheelEvent(self, event) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.view.scale(factor, factor)

    def closeEvent(self, event) -> None:
        if self._modified:
            reply = QMessageBox.question(
                self, "Несохранённые изменения",
                "Топология изменена. Сохранить перед выходом?",
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
            )
            if reply == QMessageBox.Save:
                self._save_file()
            elif reply == QMessageBox.Cancel:
                event.ignore()
                return
        event.accept()


# ─── Вспомогательные функции ─────────────────────────────────────────────────

def _is_dark(color: QColor) -> bool:
    return 0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue() < 128


# ─── Точка входа в GUI ───────────────────────────────────────────────────────

def run_gui(topology: NetworkTopology) -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Net Topology Editor")
    app.setStyle("Fusion")
    window = MainWindow(topology)
    window.show()
    sys.exit(app.exec_())
