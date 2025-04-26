import sys
import threading
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QTextEdit, QFileDialog)
from PyQt5.QtCore import Qt

from firewall import start_sniffing, stop_sniffing
from rules_manager import load_rules
import cli_dashboard as dashboard

class FirewallGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Packet Filtering Firewall - GUI Version')
        self.setGeometry(300, 100, 600, 500)
        self.initUI()

        self.sniff_thread = None

    def initUI(self):
        layout = QVBoxLayout()

        self.start_btn = QPushButton('Start Firewall')
        self.start_btn.clicked.connect(self.start_firewall)

        self.stop_btn = QPushButton('Stop Firewall')
        self.stop_btn.clicked.connect(self.stop_firewall)
        self.stop_btn.setEnabled(False)

        self.reload_rules_btn = QPushButton('Reload Rules')
        self.reload_rules_btn.clicked.connect(self.reload_rules)

        self.show_logs_btn = QPushButton('Show Logs')
        self.show_logs_btn.clicked.connect(self.show_logs)

        self.stats_label = QLabel('Total Packets: 0 | Blocked Packets: 0')
        self.stats_label.setAlignment(Qt.AlignCenter)

        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)

        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.reload_rules_btn)
        layout.addWidget(self.show_logs_btn)
        layout.addWidget(self.stats_label)
        layout.addWidget(self.logs_text)

        self.setLayout(layout)

    def start_firewall(self):
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        self.sniff_thread.start()

    def stop_firewall(self):
        stop_sniffing()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.update_stats()

    def reload_rules(self):
        load_rules()
        self.logs_text.append("Rules reloaded successfully!")

    def show_logs(self):
        try:
            with open('logs/blocked.log', 'r') as file:
                blocked_logs = file.read()
            with open('logs/allowed.log', 'r') as file:
                allowed_logs = file.read()
            with open('logs/attacks.log', 'r') as file:
                attack_logs = file.read()

            self.logs_text.clear()
            self.logs_text.append("=== Blocked Logs ===\n" + blocked_logs)
            self.logs_text.append("\n=== Allowed Logs ===\n" + allowed_logs)
            self.logs_text.append("\n=== Attack Logs ===\n" + attack_logs)

        except Exception as e:
            self.logs_text.append(f"Error reading logs: {str(e)}")

    def update_stats(self):
        total = dashboard.total_packets
        blocked = dashboard.blocked_packets
        self.stats_label.setText(f'Total Packets: {total} | Blocked Packets: {blocked}')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FirewallGUI()
    window.show()
    sys.exit(app.exec_())
