import sys,os
from PyQt5 import QtCore, QtGui, QtWidgets
from nfstream import NFStreamer
import pandas
import matplotlib


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.setWindowModality(QtCore.Qt.ApplicationModal)
        Form.resize(968, 600)
        Form.setWindowTitle(
            "Network Traffic Analysis Tool A Pure Python  Project")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(Form)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.Elements = QtWidgets.QFrame(Form)
        self.Elements.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.Elements.setObjectName("Elements")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.Elements)
        self.verticalLayout.setObjectName("verticalLayout")
        self.ToolMainLabel = QtWidgets.QLabel(self.Elements)
        palette = QtGui.QPalette()
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active,
                         QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active,
                         QtGui.QPalette.ButtonText, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(
            QtGui.QPalette.Active, QtGui.QPalette.PlaceholderText, brush
        )
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(
            QtGui.QPalette.Inactive, QtGui.QPalette.WindowText, brush
        )
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(
            QtGui.QPalette.Inactive, QtGui.QPalette.ButtonText, brush
        )
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(
            QtGui.QPalette.Inactive, QtGui.QPalette.PlaceholderText, brush
        )
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(
            QtGui.QPalette.Disabled, QtGui.QPalette.WindowText, brush
        )
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(
            QtGui.QPalette.Disabled, QtGui.QPalette.ButtonText, brush
        )
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 86))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.PlaceholderText, brush)

        ##########################################################################################

        self.ToolMainLabel.setPalette(palette)
        font = QtGui.QFont()
        font.setFamily("cmr10")
        font.setPointSize(42)
        font.setBold(True)
        font.setItalic(False)
        font.setWeight(75)
        self.ToolMainLabel.setText("Network Traffic Analysis Tool")
        self.ToolMainLabel.setFont(font)
        self.ToolMainLabel.setContextMenuPolicy(QtCore.Qt.PreventContextMenu)
        self.ToolMainLabel.setAutoFillBackground(False)
        self.ToolMainLabel.setTextFormat(QtCore.Qt.AutoText)
        self.ToolMainLabel.setAlignment(QtCore.Qt.AlignHCenter)
        self.ToolMainLabel.setIndent(0)
        self.ToolMainLabel.setTextInteractionFlags(QtCore.Qt.NoTextInteraction)
        self.ToolMainLabel.setObjectName("ToolMainLabel")
        self.verticalLayout.addWidget(self.ToolMainLabel)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding,)

        ##########################################################################################

        # Import a pcap
        self.verticalLayout.addItem(spacerItem)
        self.label3 = QtWidgets.QLabel(self.Elements)
        self.label3.setStyleSheet(
            'font: 12pt "Courier 10 Pitch"; color: rgb(0, 0, 0);')
        self.label3.setText("Are you connected?")
        self.label3.setObjectName("label3")
        self.verticalLayout.addWidget(self.label3)
        self.ImportPushButton = QtWidgets.QPushButton(self.Elements)
        self.ImportPushButton.setText("Traffic Analysis -Offline | Import Pcap")
        font = QtGui.QFont()
        font.setFamily("C059 [urw]")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.ImportPushButton.setFont(font)
        self.ImportPushButton.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.ImportPushButton.setAutoFillBackground(False)
        self.ImportPushButton.setStyleSheet("background-color: rgb(119, 118, 123);")
        self.ImportPushButton.setObjectName("ImportPushButton")
        self.verticalLayout.addWidget(self.ImportPushButton)

        # Live
        self.LiveCapturePushButton = QtWidgets.QPushButton(self.Elements)
        font = QtGui.QFont()
        font.setFamily("C059 [urw]")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.LiveCapturePushButton.setFont(font)
        self.LiveCapturePushButton.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.LiveCapturePushButton.setAutoFillBackground(False)
        self.LiveCapturePushButton.setStyleSheet("background-color: rgb(119, 118, 123);")
        self.LiveCapturePushButton.setObjectName("LiveCapturePushButton")
        self.LiveCapturePushButton.setText("Traffic Analysis -Online | Live Traffic Flow Stream")
        self.verticalLayout.addWidget(self.LiveCapturePushButton)

        ##########################################################################################

        # Nmap
        self.label2 = QtWidgets.QLabel(self.Elements)
        self.label2.setStyleSheet('font: 12pt "Courier 10 Pitch"; color: rgb(0, 0, 0);')
        self.label2.setObjectName("label2")
        self.verticalLayout.addWidget(self.label2)
        self.label2.setText("Show Hosts, Status, Ports...")
        self.NMapButton = QtWidgets.QPushButton(self.Elements)
        font = QtGui.QFont()
        font.setFamily("C059 [urw]")
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.NMapButton.setFont(font)
        self.NMapButton.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.NMapButton.setAutoFillBackground(False)
        self.NMapButton.setStyleSheet("color: rgb(255, 255, 255);\nbackground-color: rgb(50, 0, 0);\n")
        self.NMapButton.setObjectName("NMapButton")
        self.NMapButton.setText("Network Mapping | Hosts and Ports")
        self.verticalLayout.addWidget(self.NMapButton)

        ##########################################################################################

        # Covert Channels Detection
        self.label1 = QtWidgets.QLabel(self.Elements)
        self.label1.setStyleSheet('font: 12pt "Courier 10 Pitch"; color: rgb(0, 0, 0);')
        self.label1.setObjectName("label1")
        self.label1.setText("Is there any hidden data traveling in your network?")
        self.verticalLayout.addWidget(self.label1)
        self.CovertChannelsButton = QtWidgets.QPushButton(self.Elements)
        font = QtGui.QFont()
        font.setFamily("C059 [urw]")
        font.setPointSize(16)
        font.setBold(True)
        font.setItalic(False)
        font.setUnderline(False)
        font.setWeight(75)
        self.CovertChannelsButton.setFont(font)
        self.CovertChannelsButton.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.CovertChannelsButton.setAutoFillBackground(False)
        self.CovertChannelsButton.setStyleSheet("color: rgb(255, 255, 255);\nbackground-color: rgb(50, 0, 0);")
        self.CovertChannelsButton.setObjectName("CovertChannelsButton")
        self.CovertChannelsButton.setText("Detect Covert Channels")
        self.verticalLayout.addWidget(self.CovertChannelsButton)
        self.verticalLayout_2.addWidget(self.Elements)

# Automated by using the terminal command: └─$ pyuic5 -x MainGUI.ui  -o MainGUI.py
# To convert it into Python code and add the following block of code


if __name__ == "__main__":

    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
    app.quit()
    app.quitOnLastWindowClosed()
    app.setApplicationName("Network Traffic Analysis Tool")

# lines 8-10
# class Ui_Form(object):
#   def setupUi(self, Form):
#        Form.setObjectName("Form")


# def centerOnScreen(self):
#       '''Centers the window on the screen.'''
#         resolution = QApplication.desktop().screenGeometry()
#         self.move((resolution.width() / 2) - (self.frameSize().width() / 2),
#                   (resolution.height() / 2) - (self.frameSize().height() / 2))
