import csv
import io
import sys
from collections import Counter
from io import BytesIO

import matplotlib.pyplot as plt
import nfstream
import pandas as pd
import PyQt5
import PyQt6
from nfstream import NFPlugin, NFStreamer
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon, QPainter, QPixmap
from PyQt5.QtWidgets import (QApplication, QDialog, QDialogButtonBox,
                            QFileDialog, QGraphicsPixmapItem, QGraphicsScene,
                            QGraphicsView, QGroupBox, QHBoxLayout,
                            QHeaderView, QInputDialog, QLabel, QLineEdit,
                            QListWidget, QMenu, QMessageBox, QPushButton,
                            QSizePolicy, QTableWidget, QTableWidgetItem,
                            QVBoxLayout, QWidget)

from traffic_analyzer import NetworkAnalyzerApp

class Flow:
    def __init__(self, application_name, application_category_name, src_ip, dst_ip):
        self.application_name = application_name
        self.application_category_name = application_category_name
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        


class FlowTable(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels(["Application Name", "Application Category",
                "Source IP", "Destination IP"])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.setContextMenuPolicy(Qt.CustomContextMenu)  # type: ignore
        self.customContextMenuRequested.connect(self.show_context_menu)

    def update_table(self, flows):
        self.setRowCount(len(flows))

        for idx, flow in enumerate(flows):
            self.setItem(idx, 0, QTableWidgetItem(flow.application_name))
            self.setItem(idx, 1, QTableWidgetItem(flow.application_category_name))
            self.setItem(idx, 2, QTableWidgetItem(flow.src_ip))
            self.setItem(idx, 3, QTableWidgetItem(flow.dst_ip))

    def show_context_menu(self, pos):
        menu = QMenu()
        delete_row_action = menu.addAction("Delete Selected Rows")
        delete_row_action.triggered.connect(self.delete_selected_rows)
        menu.exec(self.mapToGlobal(pos))

    def delete_selected_rows(self):
        selected_rows = set(item.row() for item in self.selectedItems())
        for row in sorted(selected_rows, reverse=True):
            self.removeRow(row)

    def add_flows(self, flows):
        current_row_count = self.rowCount()
        new_row_count = current_row_count + len(flows)
        self.setRowCount(new_row_count)

        for row, flow in enumerate(flows, start=current_row_count):
            self.setItem(row, 0, QTableWidgetItem(flow.application_name))
            self.setItem(row, 1, QTableWidgetItem(flow.application_category_name))
            self.setItem(row, 2, QTableWidgetItem(flow.src_ip))
            self.setItem(row, 3, QTableWidgetItem(flow.dst_ip))

            self.resizeColumnsToContents()


# Rest of the code remains unchanged


class DropArea(QGroupBox):
    dropped = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__("Drop Area", parent)
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignCenter)  # type: ignore

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            self.dropped.emit(url.toLocalFile())


class TrafficAnalysis(QWidget):
    def __init__(self):
        super().__init__()

        self.layout = QVBoxLayout()  # type: ignore

        self.init_drop_area()
        self.init_flow_table()
        self.init_buttons()
        self.setLayout(self.layout)

    def init_drop_area(self):
        self.drop_area = DropArea()
        self.layout.addWidget(self.drop_area)
        self.drop_area.dropped.connect(self.analyze_pcap)

    def init_flow_table(self):
        self.flow_table = FlowTable()
        self.layout.addWidget(self.flow_table)
        self.flow_table.horizontalHeader().sectionClicked.connect(
            self.show_flows_dialog
        )

    def show_flows_dialog(self, column):
        dialog = QDialog(self)
        dialog.setWindowTitle("Select nfstream Flows")

        layout = QVBoxLayout()

        list_widget = QListWidget()
        layout.addWidget(list_widget)

        flow_properties = [
            "application_name",
            "application_category_name",
            "src_ip",
            "dst_ip",
            
            # Add any other nfstream flow properties you want to display
        ]

        for prop in flow_properties:
            item = QtWidgets.QListWidgetItem(prop)
            # type: ignore
            item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable) # type: ignore
            item.setCheckState(QtCore.Qt.Unchecked)  # type: ignore
            list_widget.addItem(item)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addWidget(button_box)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)

        dialog.setLayout(layout)

        result = dialog.exec()
        if result == QDialog.Accepted:
            selected_properties = [
                item.text()
                # type: ignore
                for item in list_widget.findItems("", QtCore.Qt.MatchContains) # type: ignore
                if item.checkState() == QtCore.Qt.Checked  # type: ignore
            ]  # type: ignore

            new_flows = []
            # Generate a fixed number of flows; you can adjust this value as needed.
            for _ in range(10):
                flow = Flow("-", "-", "-", "-") 
                for prop in selected_properties:
                    # Replace "example_value" with actual data from an nfstream object.
                    setattr(flow, prop, "example_value")
                new_flows.append(flow)

            self.flow_table.add_flows(new_flows)

    def init_buttons(self):
        self.buttons_group = QGroupBox("Actions")
        self.buttons_layout = QHBoxLayout()

        self.import_pcap_button = QPushButton("Import pcap")
        self.buttons_layout.addWidget(self.import_pcap_button)
        self.import_pcap_button.clicked.connect(self.import_pcap)

        self.save_csv_button = QPushButton("Save as CSV")
        self.buttons_layout.addWidget(self.save_csv_button)
        self.save_csv_button.clicked.connect(self.save_csv)

        self.generate_graph_button = QPushButton("Generate a Graph")
        self.buttons_layout.addWidget(self.generate_graph_button)
        self.generate_graph_button.clicked.connect(self.generate_graph)

        self.clear_table_button = QPushButton("Clear Table")
        self.buttons_layout.addWidget(self.clear_table_button)
        self.clear_table_button.clicked.connect(self.clear_table)

        self.advanced_button = QPushButton("Advanced mode")
        self.buttons_layout.addWidget(self.advanced_button)
        self.advanced_button.clicked.connect(self.OpenAdvance)

        self.buttons_group.setLayout(self.buttons_layout)
        self.layout.addWidget(self.buttons_group)

    def import_pcap(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_name, _ = QFileDialog.getOpenFileName(self,"Open pcap file","","pcap Files (*.pcap *.pcapng);;All Files (*)",options=options,)
        if file_name:
            self.analyze_pcap(file_name)
  
    def OpenAdvance(self):
        self.traffic_analyzer_window = NetworkAnalyzerApp()
        self.traffic_analyzer_window.show()
        self.close()

    def clear_table(self):
        self.flow_table.clearContents()
        self.flow_table.setRowCount(0)

########################################################################################################################33

    def analyze_pcap(self, file_name):
        streamer = NFStreamer(source=file_name)
        filtered_flows = self.filter_flows(streamer, )
        self.flow_table.update_table(filtered_flows)

    def save_csv(self):
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Save CSV", "", "CSV Files (*.csv);;All Files (*)"
        )
        if file_name:
            data = []
            for row in range(self.flow_table.rowCount()):
                row_data = []
                for column in range(self.flow_table.columnCount()):
                    item = self.flow_table.item(row, column)
                    if item is not None:
                        row_data.append(item.text())
                    else:
                        row_data.append("")
                data.append(row_data)
            df = pd.DataFrame(
                data,
                columns=[
                    "Application Name",
                    "Application Category",
                    "Source IP",
                    "Destination IP",
                ],
            )
            df.to_csv(file_name, index=False)

    def generate_graph(self):
        # Get the data from the flow table
        data = []
        for row in range(self.flow_table.rowCount()):
            row_data = []
            for column in range(self.flow_table.columnCount()):
                item = self.flow_table.item(row, column)
                if item is not None:
                    row_data.append(item.text())
                else:
                    row_data.append("")
            data.append(row_data)

        # Convert the data to a pandas DataFrame
        df = pd.DataFrame(
            data,
            columns=[
                "Application Name",
                "Application Category",
                "Source IP",
                "Destination IP",
            ],
        )
        # Group the data by application category and calculate the total confidence
        grouped_data = df.groupby("Application Category")["Confidence"].sum()
        # Create a bar plot of the aggregated data
        plt.figure(figsize=(10, 6))
        plt.bar(grouped_data.index, grouped_data.values)  # type: ignore
        plt.xlabel("Application Category")
        plt.ylabel("Total Confidence")
        plt.title("Traffic Analysis")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

    def filter_flows(
        self,
        streamer: NFStreamer,
        protocol: [int] = None,
        app_category: [str] = None,    ) -> [Flow]:
        flows = []
        for flow in streamer:
            if protocol is not None and flow.protocol != protocol:
                continue
            if app_category is not None and flow.application_category_name != app_category:
                continue
            flows.append(
                Flow(
                    flow.application_name,
                    flow.application_category_name,
                    flow.src_ip,
                    flow.dst_ip, # Add any other nfstream flow properties you want to display
                )
            )
        return flows
    
    
# if __name__ == "__main__":
#     app = QApplication(sys.argv)
#     main_window = TrafficAnalysis()
#     main_window.resize(1200, 800)
#     main_window.show()
#     sys.exit(app.exec())
