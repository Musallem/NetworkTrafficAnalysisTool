
import os
import queue
import subprocess
import sys
import threading
import time

import matplotlib.pyplot as plt
import nfstream
import numpy as np
import pandas as pd
import PyQt5
import seaborn as sns
from nfstream import NFStreamer
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import *
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import * 

class PcapParserThread(QThread):
    parsed = pyqtSignal(pd.DataFrame)

    def __init__(self, pcap_file):
        super().__init__()
        self.pcap_file = pcap_file

    def run(self):
        nf = NFStreamer(source=self.pcap_file, decode_tunnels=True)
        flows = nf.to_pandas()
        self.parsed.emit(flows)


class NetworkAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Analyzer")
        self.file_path = ""
        self.flows_df = None

        self.init_ui()

    def init_ui(self):
        self.create_widgets()
        self.create_layout()
        self.create_connections()

    def create_widgets(self):
        self.file_label = QLabel("No file selected")
        self.select_file_button = QPushButton("Select PCAP File")
        self.parse_button = QPushButton("Parse PCAP")
        self.clear_button = QPushButton("Clear Table")
        self.export_csv_button = QPushButton("Export to CSV")
        self.generate_graph_button = QPushButton("Generate Graph")
        self.table_view = QTableView()
        self.table_model = QStandardItemModel()
        self.table_view.setModel(self.table_model)
        self.table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_view.setEditTriggers(QTableView.NoEditTriggers)
    def create_layout(self):
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.select_file_button)
        button_layout.addWidget(self.parse_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.export_csv_button)
        button_layout.addWidget(self.generate_graph_button)

        # Main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.table_view)
        main_layout.addWidget(self.file_label)
        main_layout.addLayout(button_layout)

        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def create_connections(self):
        self.select_file_button.clicked.connect(self.select_pcap_file)
        self.parse_button.clicked.connect(self.parse_pcap)
        self.clear_button.clicked.connect(self.clear_table)
        self.export_csv_button.clicked.connect(self.export_to_csv)
        self.generate_graph_button.clicked.connect(self.generate_graph)

    def select_pcap_file(self):
        dialog = QFileDialog()
        dialog.setNameFilter("PCAP Files (*.pcap)")
        if dialog.exec_() == QFileDialog.Accepted:
            self.file_path = dialog.selectedFiles()[0]
            self.file_label.setText("Selected File: " + self.file_path)
            self.parse_button.setEnabled(True)

    def parse_pcap(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "Please select a PCAP file.")
            return

        self.parse_button.setEnabled(False)
        # Start the parsing thread
        parser_thread = PcapParserThread(self.file_path)
        parser_thread.parsed.connect(self.display_parsed_data)
        parser_thread.finished.connect(self.parse_finished)
        parser_thread.start()

        QMessageBox.information(self, "Parsing", "Parsing PCAP file. Please wait...")

    def display_parsed_data(self, flows):
        self.flows_df = flows
        self.populate_table()

    def parse_finished(self):
        self.parse_button.setEnabled(True)
        QMessageBox.information(self, "Parsing Complete", "PCAP file parsed successfully.")

    def clear_table(self):
        self.flows_df = None
        self.table_model.clear()
        QMessageBox.information(self, "Table Cleared", "Table cleared successfully.")

    def populate_table(self):
        self.table_model.clear()
        self.table_model.setColumnCount(len(self.flows_df.columns))
        # Set the header labels to be the column names WITHOUT underscores AND title case
        # Example: 'src_ip' -> 'Src Ip'
        
        self.table_model.setHorizontalHeaderLabels([col.replace("_", " ").title() for col in self.flows_df.columns])
        
        self.table_model.setHorizontalHeaderLabels(self.flows_df.columns)

        for i, row in self.flows_df.iterrows():
            for j, value in enumerate(row):
                item = QStandardItem(str(value))
                self.table_model.setItem(i, j, item)

        # Adjust column widths based on content
        self.table_view.resizeColumnsToContents()

        # Highlight specific rows or columns
        # Example: Highlight rows where protocol is 'HTTP'
        for i in range(self.table_model.rowCount()):
            if self.flows_df.iloc[i]['protocol'] == 'HTTP':
                self.table_view.setRowBackgroundColor(i, Qt.yellow)

    def export_to_csv(self):
        if self.flows_df is None:
            QMessageBox.warning(self, "Error", "No data to export.")
            return

        dialog = QFileDialog()
        dialog.setDefaultSuffix("csv")
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setNameFilter("CSV Files (*.csv)")
        if dialog.exec_() == QFileDialog.Accepted:
            file_path = dialog.selectedFiles()[0]
            self.flows_df.to_csv(file_path, index=False)
            QMessageBox.information(self, "Export Successful", "Data exported to CSV.")


    def generate_graph(self):
        if self.flows_df is None:
            QMessageBox.warning(self, "Error", "No data to generate graph.")
            return

        # Ask user for graph type
        graph_type, ok = QInputDialog.getItem(self, "Select Graph Type", "Select graph type:",
                                              ["Traffic per Application", "Traffic per Application Category", "Top Talker"],
                                              editable=False)
        if ok:
            try:
                # Traffic per application graph
                if graph_type == "Traffic per Application":
                    plt.figure(figsize=(8, 6))
                    self.flows_df['application_name'].value_counts().plot(kind='pie')
                    plt.title("Traffic per Application")
                    plt.show()
                elif graph_type == "Traffic per Application Category":
                    plt.figure(figsize=(8, 6))
                    self.flows_df['application_category_name'].value_counts().plot(kind='pie')
                    plt.title("Traffic per Application")
                    plt.show()

                # Top talker graph
                elif graph_type == "Top Talker":
                    plt.figure(figsize=(8, 6))
                    top_talker = self.flows_df['src_ip'].value_counts().head(10)
                    top_talker.plot(kind='bar')
                    plt.title("Top Talker")
                    plt.show()

            except Exception as e:
                QMessageBox.critical(self, "Error", f"An error occurred during graph generation:\n{str(e)}")


# if __name__ == "__main__":
#     app = QApplication([])
#     window = NetworkAnalyzerApp()
#     window.show()
#     app.exec_()
 