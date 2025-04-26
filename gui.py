import sys
import threading
import json
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QHBoxLayout, 
                             QTextEdit, QFileDialog, QTabWidget, QGroupBox, 
                             QGridLayout, QProgressBar, QLineEdit, QComboBox, QMessageBox, QCheckBox,
                             QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QFont, QColor
from firewall import start_sniffing, stop_sniffing, reload_firewall_rules
from rules_manager import load_rules
import cli_dashboard as dashboard
import time as time

class FirewallGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Packet Filtering Firewall - Advanced Monitor')
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QPushButton {
                background-color: #3c3f41;
                color: white;
                border: 1px solid #4c4f51;
                padding: 8px;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #4c4f51;
            }
            QPushButton:pressed {
                background-color: #2b2b2b;
            }
            QPushButton:disabled {
                background-color: #1e1e1e;
                color: #666666;
            }
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #4c4f51;
                border-radius: 4px;
            }
            QTableWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #4c4f51;
                gridline-color: #4c4f51;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #3c3f41;
                color: white;
                padding: 4px;
                border: 1px solid #4c4f51;
            }
            QLabel {
                color: #ffffff;
            }
            QGroupBox {
                border: 1px solid #4c4f51;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }
            QProgressBar {
                border: 1px solid #4c4f51;
                border-radius: 4px;
                text-align: center;
                background-color: #1e1e1e;
            }
            QProgressBar::chunk {
                background-color: #4c4f51;
            }
            QLineEdit {
                background-color: #1e1e1e;
                color: white;
                border: 1px solid #4c4f51;
                border-radius: 4px;
                padding: 5px;
            }
            QComboBox {
                background-color: #1e1e1e;
                color: white;
                border: 1px solid #4c4f51;
                border-radius: 4px;
                padding: 5px;
            }
            QCheckBox {
                color: white;
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 13px;
                height: 13px;
            }
            QTabWidget::pane {
                border: 1px solid #4c4f51;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #3c3f41;
                border: 1px solid #4c4f51;
                border-bottom-color: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 5px 10px;
            }
            QTabBar::tab:selected {
                background-color: #4c4f51;
            }
        """)
        self.initUI()
        self.sniff_thread = None
        self.firewall_status = False
        
        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_stats)
        self.update_timer.start(1000)  # Update every second
        
        # Initialize stats
        self.packet_history = {
            'total': [],
            'blocked': [],
            'allowed': []
        }
        
        # Load existing rules for display
        self.load_existing_rules()

    def initUI(self):
        main_layout = QVBoxLayout()
        
        # Top control panel with status indicator
        control_panel = QGroupBox("Firewall Controls")
        control_layout = QHBoxLayout()
        
        # Status indicator
        self.status_indicator = QLabel("● INACTIVE")
        self.status_indicator.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")
        
        self.start_btn = QPushButton('▶ Start Firewall')
        self.start_btn.clicked.connect(self.start_firewall)
        
        self.stop_btn = QPushButton('■ Stop Firewall')
        self.stop_btn.clicked.connect(self.stop_firewall)
        self.stop_btn.setEnabled(False)
        
        self.reload_rules_btn = QPushButton('↻ Reload Rules')
        self.reload_rules_btn.clicked.connect(self.reload_rules)
        
        self.export_logs_btn = QPushButton('📥 Export Logs')
        self.export_logs_btn.clicked.connect(self.export_logs)
        
        control_layout.addWidget(self.status_indicator)
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.reload_rules_btn)
        control_layout.addWidget(self.export_logs_btn)
        control_panel.setLayout(control_layout)
        
        # Main content with tabs
        self.tab_widget = QTabWidget()
        
        # Dashboard tab
        dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout()
        
        # Stats panel
        stats_panel = QGroupBox("Network Traffic Statistics")
        stats_layout = QGridLayout()
        
        self.total_packets_label = QLabel('Total Packets: 0')
        self.blocked_packets_label = QLabel('Blocked Packets: 0')
        self.allowed_packets_label = QLabel('Allowed Packets: 0')
        
        # Add progress bars for visualization
        self.blocked_progress = QProgressBar()
        self.blocked_progress.setMaximum(100)
        self.blocked_progress.setStyleSheet("QProgressBar::chunk { background-color: #d9534f; }")
        
        self.allowed_progress = QProgressBar()
        self.allowed_progress.setMaximum(100)
        self.allowed_progress.setStyleSheet("QProgressBar::chunk { background-color: #5cb85c; }")
        
        stats_layout.addWidget(self.total_packets_label, 0, 0)
        stats_layout.addWidget(QLabel("Blocked:"), 1, 0)
        stats_layout.addWidget(self.blocked_packets_label, 1, 1)
        stats_layout.addWidget(self.blocked_progress, 2, 0, 1, 2)
        stats_layout.addWidget(QLabel("Allowed:"), 3, 0)
        stats_layout.addWidget(self.allowed_packets_label, 3, 1)
        stats_layout.addWidget(self.allowed_progress, 4, 0, 1, 2)
        
        stats_panel.setLayout(stats_layout)
        dashboard_layout.addWidget(stats_panel)
        
        # Recent activity panel
        activity_panel = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout()
        
        self.activity_text = QTextEdit()
        self.activity_text.setReadOnly(True)
        self.activity_text.setFont(QFont("Consolas", 10))
        self.activity_text.setPlaceholderText("No recent activity to display")
        
        activity_layout.addWidget(self.activity_text)
        activity_panel.setLayout(activity_layout)
        dashboard_layout.addWidget(activity_panel)
        
        dashboard_tab.setLayout(dashboard_layout)
        
        # Rules tab
        rules_tab = QWidget()
        rules_layout = QVBoxLayout()
        
        # Current rules panel
        current_rules_panel = QGroupBox("Current Firewall Rules")
        current_rules_layout = QVBoxLayout()
        
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(7)
        self.rules_table.setHorizontalHeaderLabels(["#", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Action"])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        current_rules_layout.addWidget(self.rules_table)
        
        # Rules table control buttons
        rules_btn_layout = QHBoxLayout()
        
        self.delete_rule_btn = QPushButton('Delete Selected')
        self.delete_rule_btn.clicked.connect(self.delete_selected_rule)
        
        self.edit_rule_btn = QPushButton('Edit Selected')
        self.edit_rule_btn.clicked.connect(self.edit_selected_rule)
        
        rules_btn_layout.addWidget(self.delete_rule_btn)
        rules_btn_layout.addWidget(self.edit_rule_btn)
        current_rules_layout.addLayout(rules_btn_layout)
        
        current_rules_panel.setLayout(current_rules_layout)
        rules_layout.addWidget(current_rules_panel)
        
        # Add new rule panel
        new_rule_panel = QGroupBox("Add New Rule")
        new_rule_layout = QGridLayout()
        
        # Source IP/Domain
        new_rule_layout.addWidget(QLabel("Source IP/Domain:"), 0, 0)
        self.source_ip_input = QLineEdit()
        self.source_ip_input.setPlaceholderText("e.g., 192.168.1.1 or example.com")
        new_rule_layout.addWidget(self.source_ip_input, 0, 1)
        
        # Destination IP/Domain
        new_rule_layout.addWidget(QLabel("Destination IP/Domain:"), 1, 0)
        self.dest_ip_input = QLineEdit()
        self.dest_ip_input.setPlaceholderText("e.g., 192.168.1.2 or example.com")
        new_rule_layout.addWidget(self.dest_ip_input, 1, 1)
        
        # Source Port
        new_rule_layout.addWidget(QLabel("Source Port:"), 2, 0)
        self.src_port_input = QLineEdit()
        self.src_port_input.setPlaceholderText("e.g., 1234 or 'any'")
        new_rule_layout.addWidget(self.src_port_input, 2, 1)
        
        # Destination Port
        new_rule_layout.addWidget(QLabel("Destination Port:"), 3, 0)
        self.dest_port_input = QLineEdit()
        self.dest_port_input.setPlaceholderText("e.g., 80, 443 or 'any'")
        new_rule_layout.addWidget(self.dest_port_input, 3, 1)
        
        # Protocol
        new_rule_layout.addWidget(QLabel("Protocol:"), 4, 0)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP", "ICMP", "Any"])
        new_rule_layout.addWidget(self.protocol_combo, 4, 1)
        
        # Action
        new_rule_layout.addWidget(QLabel("Action:"), 5, 0)
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Block", "Allow"])
        new_rule_layout.addWidget(self.action_combo, 5, 1)
        
        # Priority checkbox
        self.priority_check = QCheckBox("High Priority Rule")
        self.priority_check.setToolTip("High priority rules are evaluated first")
        new_rule_layout.addWidget(self.priority_check, 6, 0, 1, 2)
        
        # Add Rule button
        self.add_rule_btn = QPushButton('Add Rule')
        self.add_rule_btn.clicked.connect(self.add_new_rule)
        new_rule_layout.addWidget(self.add_rule_btn, 7, 0, 1, 2)
        
        new_rule_panel.setLayout(new_rule_layout)
        rules_layout.addWidget(new_rule_panel)
        
        rules_tab.setLayout(rules_layout)
        
        # Logs tab
        logs_tab = QWidget()
        logs_layout = QVBoxLayout()
        
        # Log selection
        log_filter_layout = QHBoxLayout()
        
        self.log_type_combo = QComboBox()
        self.log_type_combo.addItems(["All Logs", "Blocked Packets", "Allowed Packets", "Attack Attempts"])
        self.log_type_combo.currentIndexChanged.connect(self.filter_logs)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search logs...")
        self.search_input.textChanged.connect(self.filter_logs)
        
        self.refresh_logs_btn = QPushButton('🔄 Refresh')
        self.refresh_logs_btn.clicked.connect(self.filter_logs)
        
        self.clear_logs_btn = QPushButton('🗑️ Clear Logs')
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        
        log_filter_layout.addWidget(QLabel("Show:"))
        log_filter_layout.addWidget(self.log_type_combo)
        log_filter_layout.addWidget(QLabel("Search:"))
        log_filter_layout.addWidget(self.search_input)
        log_filter_layout.addWidget(self.refresh_logs_btn)
        log_filter_layout.addWidget(self.clear_logs_btn)
        
        logs_layout.addLayout(log_filter_layout)
        
        # Log display
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setFont(QFont("Consolas", 10))
        
        logs_layout.addWidget(self.logs_text)
        logs_tab.setLayout(logs_layout)
        
        # Settings tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout()
        
        # General settings
        general_settings = QGroupBox("General Settings")
        gen_settings_layout = QGridLayout()
        
        self.auto_start_check = QCheckBox("Auto-start firewall on application launch")
        self.log_packets_check = QCheckBox("Log all packets (warning: high volume)")
        self.log_packets_check.setChecked(True)
        self.notify_attacks_check = QCheckBox("Show notifications for attack attempts")
        self.notify_attacks_check.setChecked(True)
        
        gen_settings_layout.addWidget(self.auto_start_check, 0, 0)
        gen_settings_layout.addWidget(self.log_packets_check, 1, 0)
        gen_settings_layout.addWidget(self.notify_attacks_check, 2, 0)
        
        general_settings.setLayout(gen_settings_layout)
        settings_layout.addWidget(general_settings)
        
        # Advanced settings
        advanced_settings = QGroupBox("Advanced Settings")
        adv_settings_layout = QGridLayout()
        
        adv_settings_layout.addWidget(QLabel("Log retention (days):"), 0, 0)
        self.log_retention = QLineEdit("30")
        adv_settings_layout.addWidget(self.log_retention, 0, 1)
        
        adv_settings_layout.addWidget(QLabel("Attack detection threshold:"), 1, 0)
        self.attack_threshold = QLineEdit("5")
        adv_settings_layout.addWidget(self.attack_threshold, 1, 1)
        
        self.save_settings_btn = QPushButton('Save Settings')
        self.save_settings_btn.clicked.connect(self.save_settings)
        adv_settings_layout.addWidget(self.save_settings_btn, 2, 0, 1, 2)
        
        advanced_settings.setLayout(adv_settings_layout)
        settings_layout.addWidget(advanced_settings)
        
        settings_tab.setLayout(settings_layout)
        
        # Add all tabs to the tab widget
        self.tab_widget.addTab(dashboard_tab, "Dashboard")
        self.tab_widget.addTab(rules_tab, "Rules Manager")
        self.tab_widget.addTab(logs_tab, "Logs")
        self.tab_widget.addTab(settings_tab, "Settings")
        
        # Add all components to main layout
        main_layout.addWidget(control_panel)
        main_layout.addWidget(self.tab_widget)
        
        self.setLayout(main_layout)

    def add_new_rule(self):
        try:
            # Get values from inputs
            src_ip = self.source_ip_input.text() or "any"
            dest_ip = self.dest_ip_input.text() or "any"
            src_port = self.src_port_input.text() or "any"
            dest_port = self.dest_port_input.text() or "any"
            protocol = self.protocol_combo.currentText()
            action = self.action_combo.currentText().lower()
            priority = self.priority_check.isChecked()
            
            # Validate ports if provided
            for port, name in [(src_port, "Source"), (dest_port, "Destination")]:
                if port != "any":
                    try:
                        port_val = int(port)
                        if not (0 <= port_val <= 65535):
                            raise ValueError(f"{name} port must be between 0 and 65535")
                    except ValueError:
                        QMessageBox.warning(self, "Invalid Port", f"{name} port must be a number between 0 and 65535")
                        return
            
            # Create new rule
            new_rule = {
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "src_port": src_port,
                "dest_port": dest_port,
                "protocol": protocol,
                "action": action,
                "priority": priority
            }
            
            # Load existing rules
            try:
                with open('rules.json', 'r') as file:
                    rules = json.load(file)
            except (FileNotFoundError, json.JSONDecodeError):
                rules = []
            
            # Add new rule
            if priority:
                # Insert at beginning if high priority
                rules.insert(0, new_rule)
            else:
                rules.append(new_rule)
            
            # Save updated rules
            with open('rules.json', 'w') as file:
                json.dump(rules, file, indent=4)
            
            # Clear inputs
            self.source_ip_input.clear()
            self.dest_ip_input.clear()
            self.src_port_input.clear()
            self.dest_port_input.clear()
            self.protocol_combo.setCurrentIndex(0)
            self.action_combo.setCurrentIndex(0)
            self.priority_check.setChecked(False)
            
            # Show success message
            QMessageBox.information(self, "Success", "New rule added successfully!")
            
            # Reload rules
            self.reload_rules()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add rule: {str(e)}")

    def load_existing_rules(self):
        try:
            with open('rules.json', 'r') as file:
                rules = json.load(file)
                
            self.rules_table.setRowCount(0)
            for i, rule in enumerate(rules):
                row_position = self.rules_table.rowCount()
                self.rules_table.insertRow(row_position)
                
                # Rule number
                self.rules_table.setItem(row_position, 0, QTableWidgetItem(str(i+1)))
                # Source IP
                self.rules_table.setItem(row_position, 1, QTableWidgetItem(rule.get('src_ip', 'any')))
                # Destination IP
                self.rules_table.setItem(row_position, 2, QTableWidgetItem(rule.get('dest_ip', 'any')))
                # Source Port
                self.rules_table.setItem(row_position, 3, QTableWidgetItem(rule.get('src_port', 'any')))
                # Destination Port
                self.rules_table.setItem(row_position, 4, QTableWidgetItem(rule.get('dest_port', 'any')))
                # Protocol
                self.rules_table.setItem(row_position, 5, QTableWidgetItem(rule.get('protocol', 'Any')))
                # Action
                action_item = QTableWidgetItem(rule.get('action', 'allow').capitalize())
                if rule.get('action') == 'block':
                    action_item.setForeground(QColor('#d9534f'))  # Red for block
                else:
                    action_item.setForeground(QColor('#5cb85c'))  # Green for allow
                self.rules_table.setItem(row_position, 6, action_item)
                
                # Highlight high priority rules
                if rule.get('priority', False):
                    for col in range(7):
                        item = self.rules_table.item(row_position, col)
                        font = item.font()
                        font.setBold(True)
                        item.setFont(font)
                
        except (FileNotFoundError, json.JSONDecodeError):
            self.rules_table.setRowCount(0)
            self.activity_text.append("No rules file found or invalid format. Starting with empty rules.")

    def delete_selected_rule(self):
        selected_rows = self.rules_table.selectionModel().selectedRows()
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a rule to delete.")
            return
            
        try:
            # Get rule index
            row_index = selected_rows[0].row()
            rule_number = int(self.rules_table.item(row_index, 0).text()) - 1
            
            # Load rules
            with open('rules.json', 'r') as file:
                rules = json.load(file)
                
            # Delete the rule
            deleted_rule = rules.pop(rule_number)
            
            # Save updated rules
            with open('rules.json', 'w') as file:
                json.dump(rules, file, indent=4)
                
            # Reload rules table
            self.load_existing_rules()
            
            # Show success message
            QMessageBox.information(self, "Success", f"Rule #{rule_number+1} deleted successfully!")
            
            # Reload rules in the firewall
            self.reload_rules()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete rule: {str(e)}")

    def edit_selected_rule(self):
        selected_rows = self.rules_table.selectionModel().selectedRows()
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select a rule to edit.")
            return
            
        try:
            # Get rule index
            row_index = selected_rows[0].row()
            rule_number = int(self.rules_table.item(row_index, 0).text()) - 1
            
            # Load rules
            with open('rules.json', 'r') as file:
                rules = json.load(file)
                
            # Get selected rule
            rule = rules[rule_number]
            
            # Fill form with rule data
            self.source_ip_input.setText(rule.get('src_ip', 'any'))
            self.dest_ip_input.setText(rule.get('dest_ip', 'any'))
            self.src_port_input.setText(rule.get('src_port', 'any'))
            self.dest_port_input.setText(rule.get('dest_port', 'any'))
            
            # Set protocol
            protocol_index = self.protocol_combo.findText(rule.get('protocol', 'Any'))
            self.protocol_combo.setCurrentIndex(protocol_index if protocol_index >= 0 else 0)
            
            # Set action
            action_index = self.action_combo.findText(rule.get('action', 'allow').capitalize())
            self.action_combo.setCurrentIndex(action_index if action_index >= 0 else 1)
            
            # Set priority
            self.priority_check.setChecked(rule.get('priority', False))
            
            # Delete the old rule
            rules.pop(rule_number)
            
            # Save updated rules
            with open('rules.json', 'w') as file:
                json.dump(rules, file, indent=4)
                
            # Reload rules table
            self.load_existing_rules()
            
            # Show info message
            QMessageBox.information(self, "Edit Rule", f"Rule #{rule_number+1} loaded for editing. Make your changes and click 'Add Rule'.")
            
            # Reload rules in the firewall
            self.reload_rules()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to edit rule: {str(e)}")

    def start_firewall(self):
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.firewall_status = True
        self.status_indicator.setText("● ACTIVE")
        self.status_indicator.setStyleSheet("color: #5cb85c; font-weight: bold; font-size: 14px;")
        
        # Start packet sniffing in a separate thread
        self.sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        self.sniff_thread.start()
        
        self.activity_text.append("[" + time.strftime("%H:%M:%S") + "] Firewall monitoring started...")
        self.logs_text.append("[" + time.strftime("%H:%M:%S") + "] Firewall monitoring started...")

    def stop_firewall(self):
        stop_sniffing()
        self.firewall_status = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_indicator.setText("● INACTIVE")
        self.status_indicator.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")
        
        self.activity_text.append("[" + time.strftime("%H:%M:%S") + "] Firewall monitoring stopped.")
        self.logs_text.append("[" + time.strftime("%H:%M:%S") + "] Firewall monitoring stopped.")

    def reload_rules(self):
        reload_firewall_rules()
        self.load_existing_rules()
        self.activity_text.append("[" + time.strftime("%H:%M:%S") + "] Rules reloaded successfully!")
        self.logs_text.append("[" + time.strftime("%H:%M:%S") + "] Rules reloaded successfully!")

    def filter_logs(self):
        log_type = self.log_type_combo.currentText()
        search_text = self.search_input.text().lower()
        
        try:
            self.logs_text.clear()
            
            if log_type == "All Logs" or log_type == "Blocked Packets":
                try:
                    with open('logs/blocked.log', 'r') as file:
                        blocked_logs = file.read()
                    
                    if search_text:
                        filtered_lines = [line for line in blocked_logs.split('\n') if search_text in line.lower()]
                        blocked_logs = '\n'.join(filtered_lines)
                    
                    if blocked_logs:
                        self.logs_text.append("=== Blocked Packets ===\n" + blocked_logs)
                except FileNotFoundError:
                    self.logs_text.append("=== Blocked Packets ===\nNo logs found.")
            
            if log_type == "All Logs" or log_type == "Allowed Packets":
                try:
                    with open('logs/allowed.log', 'r') as file:
                        allowed_logs = file.read()
                    
                    if search_text:
                        filtered_lines = [line for line in allowed_logs.split('\n') if search_text in line.lower()]
                        allowed_logs = '\n'.join(filtered_lines)
                    
                    if allowed_logs:
                        self.logs_text.append("\n=== Allowed Packets ===\n" + allowed_logs)
                except FileNotFoundError:
                    self.logs_text.append("\n=== Allowed Packets ===\nNo logs found.")
            
            if log_type == "All Logs" or log_type == "Attack Attempts":
                try:
                    with open('logs/attacks.log', 'r') as file:
                        attack_logs = file.read()
                    
                    if search_text:
                        filtered_lines = [line for line in attack_logs.split('\n') if search_text in line.lower()]
                        attack_logs = '\n'.join(filtered_lines)
                    
                    if attack_logs:
                        self.logs_text.append("\n=== Attack Attempts ===\n" + attack_logs)
                except FileNotFoundError:
                    self.logs_text.append("\n=== Attack Attempts ===\nNo logs found.")

        except Exception as e:
            self.logs_text.append(f"Error reading logs: {str(e)}")

    def clear_logs(self):
        confirmation = QMessageBox.question(self, "Confirm", "Are you sure you want to clear all log files?", 
                                           QMessageBox.Yes | QMessageBox.No)
        if confirmation == QMessageBox.Yes:
            try:
                open('logs/blocked.log', 'w').close()
                open('logs/allowed.log', 'w').close()
                open('logs/attacks.log', 'w').close()
                self.logs_text.clear()
                self.logs_text.append("All logs have been cleared.")
                self.activity_text.append("[" + time.strftime("%H:%M:%S") + "] Logs cleared.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to clear logs: {str(e)}")

    def export_logs(self):
        try:
            save_path, _ = QFileDialog.getSaveFileName(self, "Export Logs", "", "Log Files (*.log);;Text Files (*.txt);;All Files (*)")
            
            if not save_path:
                return
                
            with open(save_path, 'w') as export_file:
                # Write header
                export_file.write("===== FIREWALL LOGS EXPORT =====\n")
                export_file.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Write blocked logs
                export_file.write("=== BLOCKED PACKETS ===\n")
                try:
                    with open('logs/blocked.log', 'r') as file:
                        export_file.write(file.read())
                except FileNotFoundError:
                    export_file.write("No blocked packet logs found.\n")
                
                # Write allowed logs
                export_file.write("\n=== ALLOWED PACKETS ===\n")
                try:
                    with open('logs/allowed.log', 'r') as file:
                        export_file.write(file.read())
                except FileNotFoundError:
                    export_file.write("No allowed packet logs found.\n")
                
                # Write attack logs
                export_file.write("\n=== ATTACK ATTEMPTS ===\n")
                try:
                    with open('logs/attacks.log', 'r') as file:
                        export_file.write(file.read())
                except FileNotFoundError:
                    export_file.write("No attack logs found.\n")
            
            QMessageBox.information(self, "Success", f"Logs exported successfully to {save_path}")
            self.activity_text.append(f"[{time.strftime('%H:%M:%S')}] Logs exported to {save_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export logs: {str(e)}")

    def save_settings(self):
        try:
            settings = {
                "auto_start": self.auto_start_check.isChecked(),
                "log_all_packets": self.log_packets_check.isChecked(),
                "notify_attacks": self.notify_attacks_check.isChecked(),
                "log_retention_days": int(self.log_retention.text()),
                "attack_threshold": int(self.attack_threshold.text())
            }
            
            with open('settings.json', 'w') as file:
                json.dump(settings, file, indent=4)
                
            QMessageBox.information(self, "Success", "Settings saved successfully!")
            self.activity_text.append(f"[{time.strftime('%H:%M:%S')}] Settings updated and saved.")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")

    def update_stats(self):
        # Get current stats from dashboard
        total = dashboard.total_packets
        blocked = dashboard.blocked_packets
        allowed = total - blocked
        
        # Update labels
        self.total_packets_label.setText(f'Total Packets: {total}')
        self.blocked_packets_label.setText(f'Blocked Packets: {blocked}')
        self.allowed_packets_label.setText(f'Allowed Packets: {allowed}')
        
        # Update progress bars
        if total > 0:
            blocked_percent = (blocked / total) * 100
            allowed_percent = (allowed / total) * 100
            self.blocked_progress.setValue(int(blocked_percent))
            self.allowed_progress.setValue(int(allowed_percent))
            self.blocked_progress.setFormat(f"{int(blocked_percent)}%")
            self.allowed_progress.setFormat(f"{int(allowed_percent)}%")
            
        # Update packet history for trends
        self.packet_history['total'].append(total)
        self.packet_history['blocked'].append(blocked)
        self.packet_history['allowed'].append(allowed)
        
        # Keep only last 60 entries (for 1-minute history with 1-second updates)
        if len(self.packet_history['total']) > 60:
            self.packet_history['total'] = self.packet_history['total'][-60:]
            self.packet_history['blocked'] = self.packet_history['blocked'][-60:]
            self.packet_history['allowed'] = self.packet_history['allowed'][-60:]
            
        # Check if there are recent attack logs to update activity
        self.update_activity()

    def update_activity(self):
        """Check for recent logs and update the activity panel"""
        try:
            # Check for recent attack logs
            try:
                with open('logs/attacks.log', 'r') as file:
                    attack_lines = file.readlines()
                    if attack_lines:
                        recent_attacks = attack_lines[-5:]  # Get last 5 attack logs
                        for attack in recent_attacks:
                            if attack.strip() and attack not in self.activity_text.toPlainText():
                                self.activity_text.append(f"[{time.strftime('%H:%M:%S')}] ALERT: {attack.strip()}")
            except FileNotFoundError:
                pass
                
            # Check for recent blocked packets
            try:
                with open('logs/blocked.log', 'r') as file:
                    blocked_lines = file.readlines()
                    if blocked_lines:
                        recent_blocked = blocked_lines[-3:]  # Get last 3 blocked logs
                        for blocked in recent_blocked:
                            if blocked.strip() and blocked not in self.activity_text.toPlainText():
                                self.activity_text.append(f"[{time.strftime('%H:%M:%S')}] Blocked: {blocked.strip()}")
            except FileNotFoundError:
                pass
                
        except Exception:
            # Silently fail - this is just for UI updates
            pass

    def closeEvent(self, event):
        """Handle application close event"""
        reply = QMessageBox.question(self, 'Confirm Exit',
                                     'Are you sure you want to quit? The firewall will stop monitoring.',
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Stop the firewall if it's running
            if self.firewall_status:
                stop_sniffing()
            event.accept()
        else:
            event.ignore()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FirewallGUI()
    window.show()
    sys.exit(app.exec_())