import sys
import time
import webbrowser
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import termcolor
import json
import os

class FloatingWidget(QWidget):
    def __init__(self, texts):
        super().__init__()

        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint | Qt.Tool) #for top
        # self.setWindowFlags(Qt.WindowStaysOnBottomHint | Qt.FramelessWindowHint | Qt.Tool)  ##For bottom
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setGeometry(QRect(200, 200, 200, 200))
        self.texts = texts
        self.width = 200
        self.height = 200
        self.initUI()

    def initUI(self):
        self.canvas = Canvas(self, self.width, self.height, self.texts)
        link_widget = QWidget(self)
        link_widget.setGeometry(self.width/3, self.height/3, self.width/3, self.height/3)
        link_widget.setStyleSheet('''
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #E7ECEF, stop:1 #F1F5F8);
            border-radius: 10px;
            border: 2px solid #BEC8D0;
        ''')
        link_label = QLabel(link_widget)
        #change color of link to violet
        link_label.setStyleSheet('color: #00FFFF')
        link_label.setText('<a href="https://www.google.com/">link</a>')
        link_label.setAlignment(Qt.AlignCenter)
        link_label.setTextFormat(Qt.RichText)
        link_label.setTextInteractionFlags(Qt.TextBrowserInteraction)
        link_label.setOpenExternalLinks(True)
        link_label.setFixedSize(self.width/3, self.height/3)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)
        self.setLayout(layout)
        link_label.linkActivated.connect(lambda url: self.open_website(url))

    def open_website(self, url):
        webbrowser.open_new(url)

    def mousePressEvent(self, event):
        self.offset = event.pos()

    def mouseMoveEvent(self, event):
        self.move(self.pos() + event.pos() - self.offset)

    def resizeEvent(self, event):
        self.width = self.geometry().width()
        self.height = self.geometry().height()
        self.canvas.resizeCanvas(self.width, self.height)
    

class LinkCircle(QLabel):
    clicked = pyqtSignal()

    def __init__(self, parent, url):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setCursor(Qt.PointingHandCursor)
        self.url = url

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QColor(0xFF, 0x44, 0x44))
        painter.drawEllipse(self.rect())

    def mousePressEvent(self, event):
        self.clicked.emit()

class Canvas(QLabel):
    def __init__(self, parent, width, height, texts):
        super().__init__(parent)
        self.width = width
        self.height = height
        self.texts = texts
        self.initUI()

    def initUI(self):
        self.setMinimumSize(self.width, self.height)
        self.setMaximumSize(self.width, self.height)
        self.setScaledContents(True)
        self.create_sections()

    def create_sections(self):
        colors = [QColor(0xFF, 0x44, 0x44), QColor(0x44, 0x44, 0xFF), QColor(0x44, 0xFF, 0x44), QColor(0xFF, 0xA5, 0x00)]
        pixmap = QPixmap(self.width, self.height)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        for i in range(4):
            start_angle = i * 90 + 45
            end_angle = (i+1) * 90 + 45
            color = colors[i]
            arc_path = QPainterPath()
            arc_path.moveTo(self.width/2, self.height/2)
            arc_path.arcTo(0, 0, self.width, self.height, start_angle, 90)
            arc_path.lineTo(self.width/2, self.height/2)
            arc_path.closeSubpath()
            painter.fillPath(arc_path, color)
            if i == 0:
                x = int(self.width * 0.45)
                y = int(self.height * 0.05)
            elif i == 1:
                x = int(self.width * 0.15)
                y = int(self.height * 0.35)
            elif i == 2:
                x = int(self.width * 0.45)
                y = int(self.height * 0.7)
            else:
                x = int(self.width * 0.75)
                y = int(self.height * 0.35 )
            painter.setPen(Qt.white)
            painter.setFont(QFont('Arial', 12, QFont.Bold))
            text_rect = QRectF(x, y, self.width/3, self.height/3)
            painter.drawText(text_rect, Qt.AlignLeft | Qt.AlignVCenter, self.texts[i])
        painter.end()
        self.setPixmap(pixmap)

    def update_sections(self, new_texts):
        self.texts=new_texts
        self.create_sections()

    def resizeCanvas(self, width, height):
        self.width = width
        self.height = height
        self.setMinimumSize(self.width, self.height)
        self.setMaximumSize(self.width, self.height)
        self.create_sections()


class UpdatesToExecute:

    def __init__(self):
        if not os.path.exists('./modules/widget/visuals.json'):
            data = {
                'texts': ['A1', 'A2', 'A3', 'A4'],
                'color': None
            }
            with open('./modules/widget/visuals.json', 'w') as f:
                json.dump(data, f)
        with open('./modules/widget/visuals.json', 'r') as f:
            data = json.load(f)
        self.texts = data['texts']
        self.color = data['color']
        UpdatesToExecute.instance = self
        self.fw = FloatingWidget(self.texts)
        self.fw.show()

    @staticmethod
    def update_texts():
        instance = UpdatesToExecute.instance
        with open('./modules/widget/visuals.json', 'r') as f:
            data = json.load(f)
        instance.texts = data['texts']
        instance.color = data['color']
        instance.fw.canvas.update_sections(instance.texts)

def update(texts, color=None):
    data = {
        'texts': texts,
        'color': color
    }
    print(data)
    with open('./modules/widget/visuals.json', 'w') as f:
        json.dump(data, f)

if __name__ == '__main__':
    app = QApplication(sys.argv)

    updates_to_execute = UpdatesToExecute()

    # Schedule the update of the widget's text every 2 seconds
    timer = QTimer()
    timer.timeout.connect(lambda: updates_to_execute.update_texts())
    timer.start(2000)
    app.exec_()