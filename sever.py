import os
import socket
import threading
import traceback
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, 
                            QLabel, QTextEdit, QPushButton, QFileDialog, QMessageBox)

class FileReceiverServer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.server_socket = None
        self.running = False
        self.private_key = None
        
    def initUI(self):
        self.setWindowTitle('File Receiver Server')
        self.setGeometry(100, 100, 600, 400)
        
        layout = QVBoxLayout()
        
        self.status_label = QLabel('Server Status: Stopped')
        layout.addWidget(self.status_label)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        
        self.load_key_button = QPushButton('Load Private Key')
        self.load_key_button.clicked.connect(self.load_private_key)
        layout.addWidget(self.load_key_button)
        
        self.start_button = QPushButton('Start Server')
        self.start_button.clicked.connect(self.toggle_server)
        layout.addWidget(self.start_button)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        
    def load_private_key(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select Private Key File", "", "PEM Files (*.pem)")
            if file_path:
                with open(file_path, 'rb') as key_file:
                    self.private_key = load_pem_private_key(
                        key_file.read(),
                        password=None
                    )
                self.log_text.append(f"Private key loaded from {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load private key: {str(e)}")
            self.log_text.append(f"Key load error: {traceback.format_exc()}")
    
    def toggle_server(self):
        if self.running:
            self.stop_server()
        else:
            self.start_server()
    
    def start_server(self):
        if not self.private_key:
            QMessageBox.warning(self, "Warning", "Please load private key first!")
            return
            
        try:
            self.running = True
            self.start_button.setText('Stop Server')
            self.status_label.setText('Server Status: Running')
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('172.16.71.212', 12345))
            self.server_socket.listen(1)

            self.log_text.append(f"Server started on 172.16.71.212:12345")

            server_thread = threading.Thread(target=self.accept_connections, daemon=True)
            server_thread.start()

        except Exception as e:
            self.running = False
            QMessageBox.critical(self, "Error", f"Failed to start server: {str(e)}")
            self.log_text.append(f"Start server error: {traceback.format_exc()}")
    
    def stop_server(self):
        self.running = False
        self.start_button.setText('Start Server')
        self.status_label.setText('Server Status: Stopped')
        
        try:
            if self.server_socket:
                self.server_socket.close()
                self.log_text.append("Server stopped")
        except:
            pass
    
    def accept_connections(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                self.log_text.append(f"Connection from {addr}")
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    self.log_text.append(f"Accept error: {str(e)}")
                break
    
    def handle_client(self, conn, addr):
        try:
            # Nhận tên file
            file_name = conn.recv(1024).decode()
            conn.send(b'OK')
            
            # Nhận chữ ký
            signature = conn.recv(1024)
            conn.send(b'OK')
            
            # Nhận file data
            file_data = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                file_data += chunk
            
            # Xác minh chữ ký
            try:
                self.private_key.verify(
                    signature,
                    file_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                # Lưu file
                save_path = os.path.join('received_files', file_name)
                os.makedirs('received_files', exist_ok=True)
                
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                
                self.log_text.append(f"File {file_name} received and verified from {addr}")
                
            except Exception as e:
                self.log_text.append(f"Signature verification failed: {str(e)}")
            
        except Exception as e:
            self.log_text.append(f"Client handling error: {str(e)}")
        finally:
            try:
                conn.close()
            except:
                pass

if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    server = FileReceiverServer()
    server.show()
    sys.exit(app.exec_())