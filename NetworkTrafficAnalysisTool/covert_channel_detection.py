import joblib
import pyshark
from sklearn.impute import KNNImputer
import pandas as pd
import os
from tabulate import tabulate
import sys
from os.path import dirname, realpath, join
from PyQt5.QtWidgets import QApplication, QWidget, QTableWidget, QTableWidgetItem, QFileDialog
from PyQt5.uic import loadUiType

# Write model path
TCP_model = joblib.load('rfmodel_trained_seq_chk_ack.joblib')
TCP_model.feature_names = ['ip_id', 'tcp_seq', 'tcp_seq_raw', 'tcp_ack', 'tcp_ack_raw',
                 'tcp_len', 'tcp_hdr_len', 'tcp_flags_syn', 'tcp_flags_ack', 'tcp_checksum']

# Write model path
IP_model = joblib.load('decision_tree_trained.joblib')
IP_model.feature_names = ['ip_id', 'ip_ttl', 'ip_checksum', 'ip_flags']


def tcp_features_extraction(pkt):
    if 'TCP' in pkt and 'IP' in pkt:
        ip_id = int(pkt.ip.id, 16)
        tcp_seq = pkt.tcp.seq
        tcp_seq_raw = pkt.tcp.seq_raw
        tcp_ack = pkt.tcp.ack
        tcp_ack_raw = pkt.tcp.ack_raw
        tcp_len = pkt.tcp.len
        tcp_hdr_len = pkt.tcp.hdr_len
        tcp_flags_syn = pkt.tcp.flags_syn
        tcp_flags_ack = pkt.tcp.flags_ack
        tcp_checksum = int(pkt.tcp.checksum, 16)




        df = pd.DataFrame({
            'ip_id': [ip_id],
            'tcp_seq': [tcp_seq],
            'tcp_seq_raw': [tcp_seq_raw],
            'tcp_ack': [tcp_ack],
            'tcp_ack_raw': [tcp_ack_raw],
            'tcp_len': [tcp_len],
            'tcp_hdr_len': [tcp_hdr_len],
            'tcp_flags_syn': [tcp_flags_syn],
            'tcp_flags_ack': [tcp_flags_ack],
            'tcp_checksum': [tcp_checksum]
        })
        return df
    else:
        return None

def ip_features_extraction(pkt):
    if pkt.transport_layer:
        ip_id = int(pkt.ip.id, 16)
        ip_ttl = pkt.ip.ttl
        ip_checksum = int(pkt.ip.checksum, 16)
        ip_flags = int(pkt.ip.flags, 16)


        df = pd.DataFrame({
            'ip_id': [ip_id],
            'ip_ttl': [ip_ttl],
            'ip_checksum': [ip_checksum],
            'ip_flags': [ip_flags]
        })
        return df
    else:
        return None

imputer = KNNImputer()



scriptDir = dirname(realpath(__file__))
From_Main, _ = loadUiType(join(dirname(__file__), "DetectCovertChannel.ui"))

class MainWindow(QWidget, From_Main):
    def __init__(self):
        super(MainWindow, self).__init__()
        QWidget.__init__(self)
        self.setupUi(self)

        self.ButtonOpen.clicked.connect(self.OpenFile)
        self.BtnDescribe.clicked.connect(self.dataHead_tcp)
        self.BtnDescribe1.clicked.connect(self.dataHead_ip)

    def OpenFile(self):
        try:
            path = QFileDialog.getOpenFileName(self, 'Open PCAP', os.getenv('HOME'), 'PCAP (*.pcapng *.pcap )')[0]


            if not os.path.isfile(path):
                print('Error: File does not exist')
                exit()

            input_pcap = pyshark.FileCapture(path)
            packet_details = []
            packet_num = 0

            for pkt in input_pcap:
                fields = {
                    'Packet Number': packet_num,
                    'Time': pkt.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'Source IP': pkt.ip.src if 'IP' in pkt else '',
                    'Destination IP': pkt.ip.dst if 'IP' in pkt else '',
                    'Source Port': pkt[pkt.transport_layer].srcport if pkt.transport_layer else '',
                    'Destination Port': pkt[pkt.transport_layer].dstport if pkt.transport_layer else '',
                    'Protocol': pkt.transport_layer if pkt.transport_layer else pkt.highest_layer
                }
                packet_details.append(fields)
                packet_num += 1

            if packet_details:

                packet_table = tabulate(packet_details, headers='keys', tablefmt='psql', showindex=True)
                # print(packet_table)
            else:
                print('No packets found.')

            input_pcap.reset()

            tcp_X = pd.DataFrame(
                columns=['ip_id', 'tcp_seq', 'tcp_seq_raw', 'tcp_ack', 'tcp_ack_raw', 'tcp_len', 'tcp_hdr_len',
                         'tcp_flags_syn', 'tcp_flags_ack', 'tcp_checksum'])
            ip_X = pd.DataFrame(columns=['ip_id', 'ip_ttl', 'ip_checksum', 'ip_flags'])

            for pkt in input_pcap:
                if 'TCP' in pkt:
                    tcp_packet_features = tcp_features_extraction(pkt)
                    if tcp_packet_features is not None:
                        tcp_X = pd.concat([tcp_X, tcp_packet_features], ignore_index=True)
                    else:
                        pass

                elif 'IP' in pkt:
                    ip_packet_features = ip_features_extraction(pkt)
                    if ip_packet_features is not None:
                        ip_X = pd.concat([ip_X, ip_packet_features], ignore_index=True)
                    else:
                        pass
                else:
                    pass

            if not tcp_X.empty:
                imputer = KNNImputer()
                tcp_X[['ip_id', 'tcp_seq', 'tcp_seq_raw',
                       'tcp_ack', 'tcp_ack_raw', 'tcp_len', 'tcp_hdr_len',
                       'tcp_flags_syn', 'tcp_flags_ack', 'tcp_checksum']] = imputer.fit_transform(
                    tcp_X[['ip_id', 'tcp_seq',
                           'tcp_seq_raw', 'tcp_ack',
                           'tcp_ack_raw', 'tcp_len',
                           'tcp_hdr_len', 'tcp_flags_syn',
                           'tcp_flags_ack', 'tcp_checksum']])

            class_label = {0: "covert", 1: "normal"}

            if not ip_X.empty:
                imputer = KNNImputer()
                ip_X[['ip_id', 'ip_ttl', 'ip_checksum', 'ip_flags']] = imputer.fit_transform(
                    ip_X[['ip_id', 'ip_ttl', 'ip_checksum', 'ip_flags']])

            if not tcp_X.empty:
                tcp_predictions = TCP_model.predict(tcp_X)
                tcp_prediction_probs = TCP_model.predict_proba(tcp_X)
                tcp_prediction_probs_max = tcp_prediction_probs.max(axis=1)

                tcp_X['prediction'] = tcp_predictions
                tcp_X['prediction'] = tcp_X['prediction'].map(class_label)
                tcp_X['confidence_score'] = tcp_prediction_probs_max

                tcp_table = tabulate(tcp_X, headers='keys')
                print(tcp_table)
                self.all_data_tcp = tcp_X
            else:
                print('No TCP packets found.')
                tcp_predictions = []

            if not ip_X.empty:
                ip_predictions = IP_model.predict(ip_X)
                ip_prediction_probs = IP_model.predict_proba(ip_X)
                ip_prediction_probs_max = ip_prediction_probs.max(axis=1)

                ip_X['prediction'] = ip_predictions
                ip_X['prediction'] = ip_X['prediction'].map(class_label)
                ip_X['confidence_score'] = ip_prediction_probs_max
                # format ip detection
                ip_table = tabulate(ip_X, headers='keys')
                print(ip_table)
                self.all_data_ip = ip_X
            else:
                print('No IP packets found.')
                ip_predictions = []

        except:
            print(path)

    def dataHead_tcp(self):
        numColomn = self.spinBox.value()
        if numColomn == 0:
            NumRows = len(self.all_data_tcp.index)
        else:
            NumRows = numColomn
        self.tableWidget.setColumnCount(len(self.all_data_tcp.columns))
        self.tableWidget.setRowCount(NumRows)
        self.tableWidget.setHorizontalHeaderLabels(self.all_data_tcp.columns)

        for i in range(NumRows):
            for j in range(len(self.all_data_tcp.columns)):
                self.tableWidget.setItem(i, j, QTableWidgetItem(str(self.all_data_tcp.iat[i, j])))

        self.tableWidget.resizeColumnsToContents()
        self.tableWidget.resizeRowsToContents()

    def dataHead_ip(self):
        numColomn = self.spinBox_2.value()
        if numColomn == 0:
            NumRows = len(self.all_data_ip.index)
        else:
            NumRows = numColomn
        self.tableWidget_2.setColumnCount(len(self.all_data_ip.columns))
        self.tableWidget_2.setRowCount(NumRows)
        self.tableWidget_2.setHorizontalHeaderLabels(self.all_data_ip.columns)

        for i in range(NumRows):
            for j in range(len(self.all_data_ip.columns)):
                self.tableWidget_2.setItem(i, j, QTableWidgetItem(str(self.all_data_ip.iat[i, j])))

        self.tableWidget_2.resizeColumnsToContents()
        self.tableWidget_2.resizeRowsToContents()


app = QApplication(sys.argv)
sheet = MainWindow()
sheet.show()
sys.exit(app.exec_())
