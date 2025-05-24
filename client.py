import os
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, 
                            QLabel, QTextEdit, QPushButton, QFileDialog, 
                            QLineEdit)

class FileSenderClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.public_key = None
        
    def initUI(self):
        self.setWindowTitle('File Sender Client')
        self.setGeometry(100, 100, 600, 400)
        
        layout = QVBoxLayout()
        
        self.server_ip_label = QLabel('Server IP:')
        layout.addWidget(self.server_ip_label)
        
        self.server_ip_input = QLineEdit('172.16.71.212')
        layout.addWidget(self.server_ip_input)
        self.load_key_button = QPushButton('Load Private Key')
        self.load_key_button.clicked.connect(self.load_private_key)
        layout.addWidget(self.load_key_button)
        
        self.select_file_button = QPushButton('Select File to Send')
        self.select_file_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_file_button)
        
        self.send_button = QPushButton('Send File')
        self.send_button.clicked.connect(self.send_file)
        self.send_button.setEnabled(False)
        layout.addWidget(self.send_button)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        self.test_button = QPushButton('Test Connection')
        self.test_button.clicked.connect(self.test_connection)
        layout.addWidget(self.test_button)

    def test_connection(self):
        server_ip = self.server_ip_input.text()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)  # Timeout 2 giây
                s.connect((server_ip, 12345))
                s.close()
            self.log_text.append(f"Kết nối thành công đến {server_ip}:12345")
        except Exception as e:
            self.log_text.append(f"Lỗi kết nối đến {server_ip}:12345 - {str(e)}")
        
    def load_private_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Private Key File", "", "PEM Files (*.pem)")
        if file_path:
            try:
                with open(file_path, 'rb') as key_file:
                    self.private_key = load_pem_private_key(
                        key_file.read(),
                        password=None
                    )
                self.log_text.append(f"Private key loaded from {file_path}")
            except Exception as e:
                self.log_text.append(f"Error loading private key: {str(e)}")

# Đổi tên nút trong initUI
        self.load_key_button = QPushButton('Load Private Key')  # Thay vì 'Load Public Key'
        self.load_key_button.clicked.connect(self.load_private_key)
    def select_file(self):
        self.file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Send", "", "All Files (*)")
        if self.file_path:
            self.log_text.append(f"Selected file: {self.file_path}")
            self.send_button.setEnabled(True)
    
    def send_file(self):
        if not hasattr(self, 'file_path') or not self.private_key:  # Kiểm tra private key
            self.log_text.append("Please select a file and load private key first!")
            return
        try:
            with open(self.file_path, 'rb') as f:
                file_data = f.read()
        
        # Sử dụng private key để ký
            signature = self.private_key.sign(
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Kết nối tới server
            server_ip = self.server_ip_input.text()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server_ip, 12345))
                
                # Gửi tên file
                file_name = os.path.basename(self.file_path)
                s.send(file_name.encode())
                response = s.recv(1024)
                
                if response != b'OK':
                    raise Exception("Server didn't acknowledge file name")
                
                # Gửi chữ ký
                s.send(signature)
                response = s.recv(1024)
                
                if response != b'OK':
                    raise Exception("Server didn't acknowledge signature")
                
                # Gửi file data
                s.sendall(file_data)
            
            self.log_text.append(f"File {file_name} sent successfully to {server_ip}")
            
        except Exception as e:
            self.log_text.append(f"Error sending file: {str(e)}")

if __name__ == '__main__':
    app = QApplication([])
    client = FileSenderClient()
    client.show()
    app.exec_()