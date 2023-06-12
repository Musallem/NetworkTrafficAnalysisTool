import sys
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtCore import QThread
from PyQt5.QtWidgets import QWidget, QMainWindow, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QMessageBox, QFileDialog, QApplication
from scapy.all import sniff, wrpcap

class PacketCaptureThread(QThread):
    packetCaptured = QtCore.pyqtSignal(object)
    
    def __init__(self, iface):
        super(PacketCaptureThread, self).__init__()
        self.iface = iface
        self.captured_packets = []
    
    def packet_handler(self, packet):
        self.captured_packets.append(packet)
        self.packetCaptured.emit(packet)
    
    def run(self):
        # Capture live traffic on a specific network interface
        print(self.iface)
        sniff(iface=self.iface, prn=self.packet_handler, store=False)
        
class LiveCaptureWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.packet_counter = 0
        self.packet_capture_thread = None

        layout = QVBoxLayout()

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(2)
        self.packet_table.setHorizontalHeaderLabels(["Packet", "Summary"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.verticalHeader().setVisible(False)

        layout.addWidget(self.packet_table)

        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop Capture")
        self.export_btn = QPushButton("Export PCAP")
        layout_buttons = QHBoxLayout()
        layout_buttons.addWidget(self.start_btn)
        layout_buttons.addWidget(self.stop_btn)
        layout_buttons.addWidget(self.export_btn)
        layout.addLayout(layout_buttons)

        self.setLayout(layout)

        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.export_btn.clicked.connect(self.export_pcap)

    def packet_captured(self, packet):
        # Process the captured packet here
        packet_summary = packet.summary()

        # Append the packet information to the table
        self.packet_counter += 1
        self.packet_table.insertRow(self.packet_counter - 1)
        self.packet_table.setItem(self.packet_counter - 1, 0, QTableWidgetItem(str(self.packet_counter)))
        self.packet_table.setItem(self.packet_counter - 1, 1, QTableWidgetItem(packet_summary))

    def start_capture(self):
        if self.packet_capture_thread and self.packet_capture_thread.isRunning():
            return

        # Create a new packet capture thread
        self.packet_capture_thread = PacketCaptureThread(iface='WiFi')

        # Connect the packetCaptured signal to the packet_captured slot
        self.packet_capture_thread.packetCaptured.connect(self.packet_captured)

        # Start the packet capture thread
        self.packet_capture_thread.start()

    def stop_capture(self):
        if self.packet_capture_thread and self.packet_capture_thread.isRunning():
            self.packet_capture_thread.terminate()
            self.packet_capture_thread.wait()

    def export_pcap(self):
        if self.packet_capture_thread and self.packet_capture_thread.isRunning():
            QMessageBox.warning(self, "Capture in Progress", "Please stop the capture before exporting.")
            return

        if self.packet_counter == 0:
            QMessageBox.warning(self, "No Packets", "No packets have been captured.")
            return

        # Prompt the user to choose a file path to save the pcap file
        file_path, _ = QFileDialog.getSaveFileName(self, "Save PCAP File", "", "PCAP Files (*.pcap)")

        # Write the captured packets to the pcap file
        if file_path:
            wrpcap(file_path, self.packet_capture_thread.captured_packets)
            QMessageBox.information(self, "Export Successful", "Packets exported successfully.")

# if __name__ == "__main__":
#     app = QApplication(sys.argv)
#     win = LiveCaptureWidget()
#     win.setWindowTitle("Live Capture")
#     win.resize(1200, 1000)
#     win.show()
#     sys.exit(app.exec())