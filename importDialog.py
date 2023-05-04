from PyQt5 import QtCore, QtGui, QtWidgets
import sys

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.setWindowTitle("Dialog", "Import A Pcap/Pcapng,,,")
        self.browse.setText("Dialog", "Browse Filesystem")
        Dialog.setMinimumSize(QtCore.QSize(461, 158))
        Dialog.setMaximumSize(QtCore.QSize(461, 158))
        self.verticalLayout = QtWidgets.QVBoxLayout(Dialog)
        self.verticalLayout.setObjectName("verticalLayout")
        
        self.browse = QtWidgets.QPushButton(Dialog)
        self.browse.setMinimumSize(QtCore.QSize(443, 30))
        self.browse.setAutoFillBackground(True)
        self.browse.setObjectName("Import")
        self.verticalLayout.addWidget(self.Import)
        self.widget = QtWidgets.QWidget(Dialog)
        self.widget.setObjectName("widget")
        self.filename = QtWidgets.QLineEdit(self.widget)
        self.filename.setGeometry(QtCore.QRect(0, 20, 443, 30))
        self.filename.setMinimumSize(QtCore.QSize(443, 30))
        self.filename.setAutoFillBackground(False)
        self.filename.setObjectName("filename")
        self.verticalLayout.addWidget(self.widget)

        QtCore.QMetaObject.connectSlotsByName(Dialog)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = Ui_Dialog()
    ui.setupUi(Dialog)
    Dialog.show()
    sys.exit(app.exec_())
