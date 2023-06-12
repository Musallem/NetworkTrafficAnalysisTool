import os
import sys
#import numpy as np
from PyQt5.QtCore import Qt
from PyQt5.uic import loadUi
from PyQt5.QtWidgets import *
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5 import QtWidgets, uic, QtCore
from PyQt5.QtGui import QPixmap, QImage, QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit
import nmap
import socket
#from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtGui import QPainter, QColor
from PyQt5.QtWidgets import QMessageBox, QFrame
from PyQt5.QtCore import QPropertyAnimation, QAbstractAnimation, QRect, QPoint, QThread, pyqtSignal
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtCore import QRunnable, QThreadPool, QObject, pyqtSignal


class Message_UI(QtWidgets.QDialog):
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        uic.loadUi("Message.ui", self)
        self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)

        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.Main_Frame.mouseMoveEvent = self.MoveWindow
        self.btnNo.clicked.connect(self.answerNo)
        self.btnYes.clicked.connect(self.answerYes)

    def MoveWindow(self, event):
        if self.isMaximized() == False:
            self.move(self.pos() + event.globalPos() - self.clickPosition)
            self.clickPosition = event.globalPos()
            event.accept()
            pass

    def mousePressEvent(self, event):
        self.clickPosition = event.globalPos()
        pass

    def answerNo(self):
        self.close()
        pass

    def answerYes(self):
        app.quit()
        self.close()
        pass


class NMapWidget(QWidget):
    def __init__(self):
        super(MainWindow, self).__init__()
        # Here we imported the QT Designer file which we made as Python GUI FIle.
        loadUi("Project.ui", self)

        self.setWindowTitle("Network Mapping")

        self.setGeometry(50, 50, 800, 600)

        # show
        self.show()
        self.stackedWidget.setCurrentWidget(self.PageCheckPort)

        # click events
        self.btnCheckPort.pressed.connect(self.displayCheckPort)
        self.btnDefineHost.pressed.connect(self.displayDefineTargetHost)
        self.btnTCP.pressed.connect(self.displayTCP)
        self.btnScanPort.pressed.connect(self.displayScanPorts)
        self.btnScanConnectedHost.pressed.connect(self.displayScanHosts)
        self.btnShowPort.pressed.connect(self.displayPortNo)
        self.btnProtocol.pressed.connect(self.displayProtocol)
        self.btnQuit.pressed.connect(self.quit)
        self.Message_Box = Message_UI()
        # self.Message_Box.btnNo.clicked.connect(self.answerNo)
        # self.Message_Box.btnYes.clicked.connect(self.answerYes)

        self.btnCheck.pressed.connect(self.CheckPort)
        self.btnTarget.pressed.connect(self.DefineTargetHost)
        self.btnScan.pressed.connect(self.TCP)
        self.btnScan_2.pressed.connect(self.ScanPorts)
        self.btnScan_3.pressed.connect(self.ScanHosts)
        self.btnScan_4.pressed.connect(self.PortNo)
        self.btnScan_5.pressed.connect(self.Protocol)
        self.btnClear.clicked.connect(self.ClearFields1)
        self.btnClear_2.clicked.connect(self.ClearFields2)
        self.btnClear_3.clicked.connect(self.ClearFields3)
        self.btnClear_4.clicked.connect(self.ClearFields4)
        self.btnClear_5.clicked.connect(self.ClearFields5)
        self.btnClear_6.clicked.connect(self.ClearFields6)
        self.btnClear_7.clicked.connect(self.ClearFields7)

    def displayCheckPort(self):
        self.stackedWidget.setCurrentWidget(self.PageCheckPort)

    def displayDefineTargetHost(self):
        self.stackedWidget.setCurrentWidget(self.PageTargetHost)

    def displayTCP(self):
        self.stackedWidget.setCurrentWidget(self.PageTCP)

    def displayScanPorts(self):
        self.stackedWidget.setCurrentWidget(self.PageScanPorts)

    def displayScanHosts(self):
        self.stackedWidget.setCurrentWidget(self.PageScanHosts)

    def displayPortNo(self):
        self.stackedWidget.setCurrentWidget(self.PageShowPortNo)

    def displayProtocol(self):
        self.stackedWidget.setCurrentWidget(self.PageShowProtocol)

    # def ClearFields(self):
    #     for i in range(self.stackedWidget.count()):
    #         tab_widget = self.stackedWidget.widget(i)
    #         for line_edit in tab_widget.findChildren(QLineEdit):
    #             line_edit.clear()
    def ClearFields1(self):
        tab_widget = self.stackedWidget.widget(0)
        for line_edit in tab_widget.findChildren(QLineEdit):
            line_edit.clear()
    def ClearFields2(self):
        tab_widget = self.stackedWidget.widget(1)
        for line_edit in tab_widget.findChildren(QLineEdit):
            line_edit.clear()
    def ClearFields3(self):
        tab_widget = self.stackedWidget.widget(2)
        for line_edit in tab_widget.findChildren(QLineEdit):
            line_edit.clear()
    def ClearFields4(self):
        tab_widget = self.stackedWidget.widget(3)
        for line_edit in tab_widget.findChildren(QLineEdit):
            line_edit.clear()
    def ClearFields5(self):
        tab_widget = self.stackedWidget.widget(4)
        for line_edit in tab_widget.findChildren(QLineEdit):
            line_edit.clear()
    def ClearFields6(self):
        tab_widget = self.stackedWidget.widget(5)
        for line_edit in tab_widget.findChildren(QLineEdit):
            line_edit.clear()
    def ClearFields7(self):
        tab_widget = self.stackedWidget.widget(6)
        for line_edit in tab_widget.findChildren(QLineEdit):
            line_edit.clear()

    def CheckPort(self):
        # Ask the user to input the target IP address
        ip_address = self.txtInputIPAdd_2.text()
        output = ""

        # Create a new nmap scanner object
        scanner = nmap.PortScanner()

        # Use nmap to scan all ports on the target machine
        scanner.scan(ip_address, arguments = '-p-')

        # Loop through each port and print whether it's open or closed
        for port in scanner[ip_address]['tcp'].keys():
            if scanner[ip_address]['tcp'][port]['state'] == 'open':
                output += f'Port {port} is open. '
                #print(f"Port {port} is open.")
            else:
                output += f'Port {port} is closed. '
                #print(f"Port {port} is closed.")
        self.txtPort.setText(output)

    def DefineTargetHost(self):

        # Ask the user to enter the IP address and port range
        target_host = self.txtTargetHost.text()
        start_port = int(self.txtStartingPort.text())
        end_port = int(self.txtEndingPort.text())
        output = ""

        # Initialize the Nmap PortScanner
        scanner = nmap.PortScanner()

        # Iterate over the selected port range and scan each port
        for port in range(start_port, end_port + 1):
        # Check if the port is open or not
            port_status = scanner.scan(target_host, str(port))
            state = port_status['scan'][target_host]['tcp'][port]['state']
            output += f"Port {port} is {state}. "
            #print(f"Port {port} is {state}")
        self.txtOutput.setText(output)

    def TCP(self):
        # create a PortScanner object
        nm = nmap.PortScanner()
        output1 = ""
        output2 = ""

        # ask user for IP address or hostname to scan
        target = self.txtIP.text()

        # perform a TCP SYN scan on all ports (1-65535)
        nm.scan(target, arguments='-sS -p 1-65535')

        # iterate over each protocol/port reported as "open", "closed", or "filtered"
        for protocol in nm[target].all_protocols():
            #print('Protocol: {}'.format(protocol))
            output1 = 'Protocol: {}'.format(protocol)

            ports = nm[target][protocol].keys()
            sorted_ports = sorted(ports)

            for port in sorted_ports:
                state = nm[target][protocol][port]['state']
                output2 += 'Port: {} \t State: {}'.format(port, state)
                #print('Port: {} \t State: {}'.format(port, state))
        self.txtProtocol.setText(output1)
        self.txtPorts.setText(output2)

    def ScanPorts(self):
        
        # Ask user for the IP address to scan
        target_ip = self.txtInputIpAdd.text()
        output = ""

        # Initialize nmap scanner
        nm = nmap.PortScanner()

        # Use nmap to scan for devices on target network
        scan_result = nm.scan(hosts=target_ip + '/24', arguments='-sn')

        # Retrieve device information from scan result
        devices = []
        for ip, info in scan_result['scan'].items():
            if 'hostnames' in info:
                hostname = info['hostnames'][0]['name']
            else:
                hostname = 'Unknown'
            devices.append({'ip': ip, 'hostname': hostname})

        # Print list of nearby devices
        #print('\nNearby devices:')
        for device in devices:
            print('IP:', device['ip'], '\tHostname:', device['hostname'])
            #output += 'IP:', device['ip'], '\tHostname:', device['hostname']
            output += "          " + 'IP: ' + str(device['ip']) + '\tHostname: ' + str(device['hostname'])

        self.txtOutputScan.setText(output)

    def ScanHosts(self):
        
        # Prompt user to input target IP address
        target_ip = self.txtInputIpAdd_3.text()
        output1 = ""
        output2 = ""
        output3 = ""
        output4 = ""

        # Initialize nmap scanner
        nm_scan = nmap.PortScanner()

        # Set nmap arguments and scan target host
        nm_scan.scan(hosts=target_ip, arguments='-v -sS')

        # Print results
        # print(f'\nHost: {target_ip} ({nm_scan[target_ip].hostname()})')
        output1 = f'\nHost: {target_ip} ({nm_scan[target_ip].hostname()})'
        output2 = f'State: {nm_scan[target_ip].state()}' 
        # print(f'State: {nm_scan[target_ip].state()}')
        for protocol in nm_scan[target_ip].all_protocols():
            #print(f'\nProtocol: {protocol}')
            output3 = f'\nProtocol: {protocol}'
            open_ports = sorted(nm_scan[target_ip][protocol].keys())
            for port in open_ports:
                #print(f'Port: {port}\tState: {nm_scan[target_ip][protocol][port]["state"]}\tService: {nm_scan[target_ip][protocol][port]["name"]}')
                output4 += "     " + f'Port: {port}\tState: {nm_scan[target_ip][protocol][port]["state"]}\tService: {nm_scan[target_ip][protocol][port]["name"]}'
    
        self.txtOutputHostIpAdd.setText(output1)
        self.txtOutputHostState.setText(output2)
        self.txtOutputHostProtocol.setText(output3)
        self.txtOutputHostPorts.setText(output4)

    def PortNo(self):
        
        # Take IP address input from user
        host = self.txtInputIpAdd_2.text()
        output1 = ""
        output2 = ""
        
        # Create a port scanner object
        scanner = nmap.PortScanner()

        # Get list of available scan methods
        output1 = scanner.nmap_version()

        # Scan for TCP ports between 1-1024
        scanner.scan(host, '1-1024', '-v')

        # Print the status of all ports
        for host in scanner.all_hosts():
            #print("IP address: ", host)
            for port in scanner[host]['tcp']:
                #output2 += "Port: ", port, " Status: ", scanner[host]['tcp'][port]['state']
                output2 += "  " + f"Port: {port} Status: {scanner[host]['tcp'][port]['state']}"
                #output2 += 'IP: ' + str(device['ip']) + '\tHostname: ' + str(device['hostname'])
        self.txtOutputIPAdd.setText(str(output1))
        self.txtOutputPortStatus.setText(output2)
        

    def Protocol(self):
        nm = nmap.PortScanner()
        output1 = ""
        output2 = ""
        output3 = ""
        output4 = ""

        ip_address = self.txtInputIPAdd.text()
        nm.scan(ip_address, arguments='-sS')

        for host in nm.all_hosts():
            #print('Host : %s (%s)' % (host, nm[host].hostname()))
            output1 += 'Host : %s (%s)' % (host, nm[host].hostname())
            #print('State : %s' % nm[host].state())
            output2 += 'State : %s' % nm[host].state()
            for proto in nm[host].all_protocols():
                #print('Protocol : %s' % proto)
                output3 += 'Protocol : %s' % proto
                lport = nm[host][proto].keys()
                sorted(lport)
                for port in lport:
                    #print('port : %s\t state : %s\t' % (port, nm[host][proto][port]['state']))
                    output4 += 'port : %s\t state : %s\t' % (
                        port, nm[host][proto][port]['state'])
        self.txtHostName.setText(output1)
        self.txtHostState.setText(output2)
        self.txtHostProtocol.setText(output3)
        self.txtHostPorts.setText(output4)

    def quit(self):
        self.Message_Box = Message_UI()
        self.Message_Box.show()

