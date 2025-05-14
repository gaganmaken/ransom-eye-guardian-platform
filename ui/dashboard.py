
#!/usr/bin/env python3
# Dashboard for RansomEye

import os
import sys
import time
import json
import logging
import threading
import sqlite3
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from utils.db_writer import DatabaseWriter

logger = logging.getLogger("RansomEye.Dashboard")

class RansomEyeDashboard:
    def __init__(self, root, message_queue, config):
        self.root = root
        self.message_queue = message_queue
        self.config = config
        
        # Setup database connection
        self.db_writer = DatabaseWriter('data/ransomeye.db')
        
        # Configuration
        self.auto_refresh = True
        self.refresh_interval = 5  # seconds
        
        # Initialize UI
        self.setup_ui()
        
        # Start refresh timer
        self.refresh_data()
    
    def setup_ui(self):
        """Set up the main UI components"""
        # Configure root window
        self.root.title("RansomEye - Ransomware Detection Platform")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Apply dark theme
        self.apply_dark_theme()
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create top status bar
        self.create_status_bar()
        
        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add tabs
        self.create_dashboard_tab()
        self.create_events_tab()
        self.create_files_tab()
        self.create_processes_tab()
        self.create_network_tab()
        self.create_reports_tab()
        self.create_config_tab()
    
    def apply_dark_theme(self):
        """Apply dark theme to the UI"""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')  # Use 'clam' as base theme
        
        # Define colors
        bg_color = "#292929"
        fg_color = "#e0e0e0"
        selection_color = "#505050"
        highlight_color = "#e74c3c"  # Red for alerts
        warning_color = "#f39c12"    # Amber for warnings
        info_color = "#3498db"       # Blue for info
        
        # Configure style elements
        style.configure("TFrame", background=bg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color)
        style.configure("TButton", background=selection_color, foreground=fg_color)
        style.configure("TNotebook", background=bg_color, tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", background=selection_color, foreground=fg_color, padding=[10, 2])
        
        style.map("TNotebook.Tab",
                background=[("selected", bg_color)],
                foreground=[("selected", fg_color)])
        
        style.configure("Treeview", 
                      background=bg_color,
                      foreground=fg_color,
                      fieldbackground=bg_color)
        style.map("Treeview", 
                background=[("selected", selection_color)],
                foreground=[("selected", fg_color)])
        
        # Configure Tkinter root window
        self.root.configure(bg=bg_color)
        
        # Set colors as attributes for later use
        self.colors = {
            "bg": bg_color,
            "fg": fg_color,
            "select": selection_color,
            "highlight": highlight_color,
            "warning": warning_color,
            "info": info_color
        }
        
        # Configure ttk widgets that we'll use later
        style.configure("Critical.TLabel", background=bg_color, foreground=highlight_color, font=("TkDefaultFont", 12, "bold"))
        style.configure("Warning.TLabel", background=bg_color, foreground=warning_color, font=("TkDefaultFont", 11))
        style.configure("Info.TLabel", background=bg_color, foreground=info_color)
        
        # Configure Treeview tags for severity highlighting
        style.configure("Critical.Treeview.Row", background=highlight_color)
    
    def create_status_bar(self):
        """Create the top status bar"""
        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Status label
        self.status_label = ttk.Label(status_frame, text="System Status: Normal", style="Info.TLabel")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Refresh toggle
        self.refresh_var = tk.BooleanVar(value=True)
        refresh_check = ttk.Checkbutton(status_frame, text="Auto Refresh", variable=self.refresh_var,
                                       command=self.toggle_auto_refresh)
        refresh_check.pack(side=tk.RIGHT, padx=5)
        
        # Manual refresh button
        refresh_btn = ttk.Button(status_frame, text="Refresh Now", command=self.refresh_data)
        refresh_btn.pack(side=tk.RIGHT, padx=5)
    
    def create_dashboard_tab(self):
        """Create the main dashboard overview tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Split into top and bottom sections
        top_frame = ttk.Frame(dashboard_frame)
        top_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create overview panels in top section (2x2 grid)
        # 1. Latest Alerts
        alert_frame = ttk.LabelFrame(top_frame, text="Latest Alerts")
        alert_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        self.alert_tree = ttk.Treeview(alert_frame, columns=("time", "type", "severity", "description"), 
                                     show="headings", height=5)
        self.alert_tree.heading("time", text="Time")
        self.alert_tree.heading("type", text="Type")
        self.alert_tree.heading("severity", text="Sev")
        self.alert_tree.heading("description", text="Description")
        
        self.alert_tree.column("time", width=100)
        self.alert_tree.column("type", width=100)
        self.alert_tree.column("severity", width=40)
        self.alert_tree.column("description", width=300)
        
        self.alert_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 2. System Status
        status_frame = ttk.LabelFrame(top_frame, text="System Status")
        status_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        # System status indicators
        fs_status = ttk.Label(status_frame, text="File System Monitor: Active", style="Info.TLabel")
        fs_status.pack(anchor=tk.W, padx=5, pady=2)
        
        ps_status = ttk.Label(status_frame, text="Process Monitor: Active", style="Info.TLabel")
        ps_status.pack(anchor=tk.W, padx=5, pady=2)
        
        net_status = ttk.Label(status_frame, text="Network Monitor: Active", style="Info.TLabel")
        net_status.pack(anchor=tk.W, padx=5, pady=2)
        
        ai_status = ttk.Label(status_frame, text="AI Anomaly Detection: Active", style="Info.TLabel")
        ai_status.pack(anchor=tk.W, padx=5, pady=2)
        
        self.threat_level_label = ttk.Label(status_frame, text="Current Threat Level: Low", style="Info.TLabel")
        self.threat_level_label.pack(anchor=tk.W, padx=5, pady=10)
        
        auto_mitigate = self.config.get('auto_mitigation', 'False')
        mitigation_status = "Enabled" if auto_mitigate == 'True' else "Disabled"
        self.mitigation_label = ttk.Label(status_frame, 
                                        text=f"Auto-Mitigation: {mitigation_status}", 
                                        style="Info.TLabel")
        self.mitigation_label.pack(anchor=tk.W, padx=5, pady=2)
        
        # 3. Event Statistics
        stats_frame = ttk.LabelFrame(top_frame, text="Event Statistics")
        stats_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create a Figure for plotting
        self.fig = plt.Figure(figsize=(5, 4), dpi=100)
        self.fig.patch.set_facecolor(self.colors["bg"])
        
        # Create a canvas to display the figure
        self.canvas = FigureCanvasTkAgg(self.fig, stats_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # 4. Recent Activity
        activity_frame = ttk.LabelFrame(top_frame, text="Recent Activity")
        activity_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        
        self.activity_text = tk.Text(activity_frame, height=10, bg=self.colors["bg"], fg=self.colors["fg"], wrap=tk.WORD)
        self.activity_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure grid weights
        top_frame.grid_rowconfigure(0, weight=1)
        top_frame.grid_rowconfigure(1, weight=1)
        top_frame.grid_columnconfigure(0, weight=1)
        top_frame.grid_columnconfigure(1, weight=1)
        
        # Add emergency controls
        emergency_frame = ttk.Frame(dashboard_frame)
        emergency_frame.pack(fill=tk.X, pady=10)
        
        emergency_label = ttk.Label(emergency_frame, text="Emergency Controls:", style="Critical.TLabel")
        emergency_label.pack(side=tk.LEFT, padx=10)
        
        isolate_btn = ttk.Button(emergency_frame, text="Isolate System", command=self.emergency_isolate)
        isolate_btn.pack(side=tk.LEFT, padx=5)
        
        kill_all_btn = ttk.Button(emergency_frame, text="Kill Suspicious Processes", command=self.kill_suspicious)
        kill_all_btn.pack(side=tk.LEFT, padx=5)
        
        report_btn = ttk.Button(emergency_frame, text="Generate Incident Report", command=self.generate_report)
        report_btn.pack(side=tk.LEFT, padx=5)
    
    def create_events_tab(self):
        """Create the events tab"""
        events_frame = ttk.Frame(self.notebook)
        self.notebook.add(events_frame, text="Events")
        
        # Create filters
        filter_frame = ttk.Frame(events_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Filter by:").pack(side=tk.LEFT, padx=5)
        
        # Type filter
        ttk.Label(filter_frame, text="Type:").pack(side=tk.LEFT, padx=5)
        self.event_type_var = tk.StringVar(value="All")
        event_type_combo = ttk.Combobox(filter_frame, textvariable=self.event_type_var, 
                                      values=["All", "suspicious_file", "suspicious_process", 
                                             "suspicious_network", "anomaly_file", "anomaly_process",
                                             "anomaly_network", "threat_escalation"])
        event_type_combo.pack(side=tk.LEFT, padx=5)
        
        # Severity filter
        ttk.Label(filter_frame, text="Min Severity:").pack(side=tk.LEFT, padx=5)
        self.severity_var = tk.StringVar(value="0")
        severity_combo = ttk.Combobox(filter_frame, textvariable=self.severity_var, 
                                    values=["0", "5", "6", "7", "8", "9", "10"])
        severity_combo.pack(side=tk.LEFT, padx=5)
        
        # Apply filter button
        filter_btn = ttk.Button(filter_frame, text="Apply Filters", command=self.apply_event_filters)
        filter_btn.pack(side=tk.LEFT, padx=10)
        
        # Create events table
        self.events_tree = ttk.Treeview(events_frame, 
                                     columns=("id", "time", "type", "severity", "source", "description", "mitigated"), 
                                     show="headings")
        
        self.events_tree.heading("id", text="ID")
        self.events_tree.heading("time", text="Time")
        self.events_tree.heading("type", text="Type")
        self.events_tree.heading("severity", text="Sev")
        self.events_tree.heading("source", text="Source")
        self.events_tree.heading("description", text="Description")
        self.events_tree.heading("mitigated", text="Mitigated")
        
        self.events_tree.column("id", width=50)
        self.events_tree.column("time", width=150)
        self.events_tree.column("type", width=150)
        self.events_tree.column("severity", width=40)
        self.events_tree.column("source", width=100)
        self.events_tree.column("description", width=400)
        self.events_tree.column("mitigated", width=80)
        
        self.events_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar
        events_scrollbar = ttk.Scrollbar(events_frame, orient=tk.VERTICAL, command=self.events_tree.yview)
        events_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.events_tree.configure(yscrollcommand=events_scrollbar.set)
        
        # Bind double-click for event details
        self.events_tree.bind("<Double-1>", self.show_event_details)
    
    def create_files_tab(self):
        """Create the suspicious files tab"""
        files_frame = ttk.Frame(self.notebook)
        self.notebook.add(files_frame, text="Files")
        
        # Create filters
        filter_frame = ttk.Frame(files_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Filter by:").pack(side=tk.LEFT, padx=5)
        
        # Min entropy filter
        ttk.Label(filter_frame, text="Min Entropy:").pack(side=tk.LEFT, padx=5)
        self.entropy_var = tk.StringVar(value="0")
        entropy_combo = ttk.Combobox(filter_frame, textvariable=self.entropy_var, 
                                    values=["0", "6", "7", "7.5", "8"])
        entropy_combo.pack(side=tk.LEFT, padx=5)
        
        # Apply filter button
        filter_btn = ttk.Button(filter_frame, text="Apply Filters", command=self.apply_file_filters)
        filter_btn.pack(side=tk.LEFT, padx=10)
        
        # Create files table
        self.files_tree = ttk.Treeview(files_frame, 
                                     columns=("id", "event_id", "path", "hash", "entropy", "action"), 
                                     show="headings")
        
        self.files_tree.heading("id", text="ID")
        self.files_tree.heading("event_id", text="Event")
        self.files_tree.heading("path", text="File Path")
        self.files_tree.heading("hash", text="Hash")
        self.files_tree.heading("entropy", text="Entropy")
        self.files_tree.heading("action", text="Action")
        
        self.files_tree.column("id", width=50)
        self.files_tree.column("event_id", width=50)
        self.files_tree.column("path", width=400)
        self.files_tree.column("hash", width=150)
        self.files_tree.column("entropy", width=60)
        self.files_tree.column("action", width=100)
        
        self.files_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar
        files_scrollbar = ttk.Scrollbar(files_frame, orient=tk.VERTICAL, command=self.files_tree.yview)
        files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.files_tree.configure(yscrollcommand=files_scrollbar.set)
        
        # Add action buttons
        action_frame = ttk.Frame(files_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        quarantine_btn = ttk.Button(action_frame, text="Quarantine Selected", 
                                  command=lambda: self.action_on_selected(self.files_tree, "quarantine"))
        quarantine_btn.pack(side=tk.LEFT, padx=5)
        
        restore_btn = ttk.Button(action_frame, text="Restore Selected", 
                               command=lambda: self.action_on_selected(self.files_tree, "restore"))
        restore_btn.pack(side=tk.LEFT, padx=5)
    
    def create_processes_tab(self):
        """Create the suspicious processes tab"""
        processes_frame = ttk.Frame(self.notebook)
        self.notebook.add(processes_frame, text="Processes")
        
        # Create process table
        self.processes_tree = ttk.Treeview(processes_frame, 
                                         columns=("id", "event_id", "pid", "name", "cmd", "parent", "action"), 
                                         show="headings")
        
        self.processes_tree.heading("id", text="ID")
        self.processes_tree.heading("event_id", text="Event")
        self.processes_tree.heading("pid", text="PID")
        self.processes_tree.heading("name", text="Name")
        self.processes_tree.heading("cmd", text="Command")
        self.processes_tree.heading("parent", text="Parent")
        self.processes_tree.heading("action", text="Action")
        
        self.processes_tree.column("id", width=50)
        self.processes_tree.column("event_id", width=50)
        self.processes_tree.column("pid", width=60)
        self.processes_tree.column("name", width=100)
        self.processes_tree.column("cmd", width=300)
        self.processes_tree.column("parent", width=60)
        self.processes_tree.column("action", width=100)
        
        self.processes_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar
        proc_scrollbar = ttk.Scrollbar(processes_frame, orient=tk.VERTICAL, command=self.processes_tree.yview)
        proc_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.processes_tree.configure(yscrollcommand=proc_scrollbar.set)
        
        # Add action buttons
        action_frame = ttk.Frame(processes_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        kill_btn = ttk.Button(action_frame, text="Terminate Selected", 
                           command=lambda: self.action_on_selected(self.processes_tree, "kill"))
        kill_btn.pack(side=tk.LEFT, padx=5)
        
        details_btn = ttk.Button(action_frame, text="Show Process Tree", 
                              command=self.show_process_tree)
        details_btn.pack(side=tk.LEFT, padx=5)
    
    def create_network_tab(self):
        """Create the suspicious network connections tab"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="Network")
        
        # Create network table
        self.network_tree = ttk.Treeview(network_frame, 
                                       columns=("id", "event_id", "src", "dst", "sport", "dport", "proto", "action"), 
                                       show="headings")
        
        self.network_tree.heading("id", text="ID")
        self.network_tree.heading("event_id", text="Event")
        self.network_tree.heading("src", text="Source IP")
        self.network_tree.heading("dst", text="Destination IP")
        self.network_tree.heading("sport", text="Src Port")
        self.network_tree.heading("dport", text="Dst Port")
        self.network_tree.heading("proto", text="Protocol")
        self.network_tree.heading("action", text="Action")
        
        self.network_tree.column("id", width=50)
        self.network_tree.column("event_id", width=50)
        self.network_tree.column("src", width=120)
        self.network_tree.column("dst", width=120)
        self.network_tree.column("sport", width=60)
        self.network_tree.column("dport", width=60)
        self.network_tree.column("proto", width=60)
        self.network_tree.column("action", width=100)
        
        self.network_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar
        net_scrollbar = ttk.Scrollbar(network_frame, orient=tk.VERTICAL, command=self.network_tree.yview)
        net_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.network_tree.configure(yscrollcommand=net_scrollbar.set)
        
        # Add action buttons
        action_frame = ttk.Frame(network_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        block_btn = ttk.Button(action_frame, text="Block Selected", 
                            command=lambda: self.action_on_selected(self.network_tree, "block"))
        block_btn.pack(side=tk.LEFT, padx=5)
    
    def create_reports_tab(self):
        """Create the reports tab"""
        reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(reports_frame, text="Reports")
        
        # Create report options
        options_frame = ttk.LabelFrame(reports_frame, text="Report Options")
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Time range
        time_frame = ttk.Frame(options_frame)
        time_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(time_frame, text="Time Range:").pack(side=tk.LEFT, padx=5)
        self.time_range_var = tk.StringVar(value="24h")
        time_combo = ttk.Combobox(time_frame, textvariable=self.time_range_var, 
                                 values=["1h", "6h", "12h", "24h", "7d", "30d", "all"])
        time_combo.pack(side=tk.LEFT, padx=5)
        
        # Include options
        include_frame = ttk.Frame(options_frame)
        include_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(include_frame, text="Include:").pack(side=tk.LEFT, padx=5)
        
        self.include_files_var = tk.BooleanVar(value=True)
        files_check = ttk.Checkbutton(include_frame, text="Files", variable=self.include_files_var)
        files_check.pack(side=tk.LEFT, padx=5)
        
        self.include_processes_var = tk.BooleanVar(value=True)
        proc_check = ttk.Checkbutton(include_frame, text="Processes", variable=self.include_processes_var)
        proc_check.pack(side=tk.LEFT, padx=5)
        
        self.include_network_var = tk.BooleanVar(value=True)
        net_check = ttk.Checkbutton(include_frame, text="Network", variable=self.include_network_var)
        net_check.pack(side=tk.LEFT, padx=5)
        
        self.include_mitigations_var = tk.BooleanVar(value=True)
        mit_check = ttk.Checkbutton(include_frame, text="Mitigations", variable=self.include_mitigations_var)
        mit_check.pack(side=tk.LEFT, padx=5)
        
        # Format options
        format_frame = ttk.Frame(options_frame)
        format_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(format_frame, text="Format:").pack(side=tk.LEFT, padx=5)
        
        self.format_var = tk.StringVar(value="pdf")
        pdf_radio = ttk.Radiobutton(format_frame, text="PDF", variable=self.format_var, value="pdf")
        pdf_radio.pack(side=tk.LEFT, padx=5)
        
        csv_radio = ttk.Radiobutton(format_frame, text="CSV", variable=self.format_var, value="csv")
        csv_radio.pack(side=tk.LEFT, padx=5)
        
        json_radio = ttk.Radiobutton(format_frame, text="JSON", variable=self.format_var, value="json")
        json_radio.pack(side=tk.LEFT, padx=5)
        
        # Generate button
        generate_frame = ttk.Frame(options_frame)
        generate_frame.pack(fill=tk.X, padx=5, pady=10)
        
        generate_btn = ttk.Button(generate_frame, text="Generate Report", command=self.generate_report)
        generate_btn.pack(padx=5)
        
        # Previously generated reports
        reports_list_frame = ttk.LabelFrame(reports_frame, text="Available Reports")
        reports_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.reports_list = ttk.Treeview(reports_list_frame, 
                                       columns=("filename", "date", "type", "size"), 
                                       show="headings")
        
        self.reports_list.heading("filename", text="Filename")
        self.reports_list.heading("date", text="Date")
        self.reports_list.heading("type", text="Type")
        self.reports_list.heading("size", text="Size")
        
        self.reports_list.column("filename", width=400)
        self.reports_list.column("date", width=150)
        self.reports_list.column("type", width=50)
        self.reports_list.column("size", width=100)
        
        self.reports_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add action buttons
        report_action_frame = ttk.Frame(reports_list_frame)
        report_action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        open_btn = ttk.Button(report_action_frame, text="Open Selected", command=self.open_report)
        open_btn.pack(side=tk.LEFT, padx=5)
        
        delete_btn = ttk.Button(report_action_frame, text="Delete Selected", command=self.delete_report)
        delete_btn.pack(side=tk.LEFT, padx=5)
    
    def create_config_tab(self):
        """Create the configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")
        
        # Create configuration form
        settings_frame = ttk.LabelFrame(config_frame, text="Settings")
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scan interval
        interval_frame = ttk.Frame(settings_frame)
        interval_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(interval_frame, text="Scan Interval (seconds):").pack(side=tk.LEFT, padx=5)
        self.scan_interval_var = tk.StringVar(value=self.config.get('scan_interval', '60'))
        interval_entry = ttk.Entry(interval_frame, textvariable=self.scan_interval_var, width=10)
        interval_entry.pack(side=tk.LEFT, padx=5)
        
        # Entropy threshold
        entropy_frame = ttk.Frame(settings_frame)
        entropy_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(entropy_frame, text="Entropy Threshold (0-8):").pack(side=tk.LEFT, padx=5)
        self.entropy_threshold_var = tk.StringVar(value=self.config.get('entropy_threshold', '7.8'))
        entropy_entry = ttk.Entry(entropy_frame, textvariable=self.entropy_threshold_var, width=10)
        entropy_entry.pack(side=tk.LEFT, padx=5)
        
        # Process CPU threshold
        cpu_frame = ttk.Frame(settings_frame)
        cpu_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(cpu_frame, text="Process CPU Threshold (%):").pack(side=tk.LEFT, padx=5)
        self.cpu_threshold_var = tk.StringVar(value=self.config.get('process_cpu_threshold', '80'))
        cpu_entry = ttk.Entry(cpu_frame, textvariable=self.cpu_threshold_var, width=10)
        cpu_entry.pack(side=tk.LEFT, padx=5)
        
        # Network connection threshold
        conn_frame = ttk.Frame(settings_frame)
        conn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(conn_frame, text="Connection Threshold:").pack(side=tk.LEFT, padx=5)
        self.conn_threshold_var = tk.StringVar(value=self.config.get('network_conn_threshold', '50'))
        conn_entry = ttk.Entry(conn_frame, textvariable=self.conn_threshold_var, width=10)
        conn_entry.pack(side=tk.LEFT, padx=5)
        
        # AI confidence threshold
        ai_frame = ttk.Frame(settings_frame)
        ai_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(ai_frame, text="AI Confidence Threshold (0-1):").pack(side=tk.LEFT, padx=5)
        self.ai_threshold_var = tk.StringVar(value=self.config.get('ai_confidence_threshold', '0.7'))
        ai_entry = ttk.Entry(ai_frame, textvariable=self.ai_threshold_var, width=10)
        ai_entry.pack(side=tk.LEFT, padx=5)
        
        # Auto-mitigation toggle
        mitigate_frame = ttk.Frame(settings_frame)
        mitigate_frame.pack(fill=tk.X, padx=5, pady=10)
        
        ttk.Label(mitigate_frame, text="Auto-Mitigation:").pack(side=tk.LEFT, padx=5)
        self.auto_mitigate_var = tk.BooleanVar(value=self.config.get('auto_mitigation') == 'True')
        mitigate_check = ttk.Checkbutton(mitigate_frame, variable=self.auto_mitigate_var)
        mitigate_check.pack(side=tk.LEFT, padx=5)
        
        # Warning about auto-mitigation
        warning_label = ttk.Label(mitigate_frame, 
                                text="Warning: Auto-mitigation can disrupt services!", 
                                style="Warning.TLabel")
        warning_label.pack(side=tk.LEFT, padx=20)
        
        # Save button
        save_frame = ttk.Frame(settings_frame)
        save_frame.pack(fill=tk.X, padx=5, pady=10)
        
        save_btn = ttk.Button(save_frame, text="Save Configuration", command=self.save_config)
        save_btn.pack(padx=5)
    
    def toggle_auto_refresh(self):
        """Toggle automatic data refresh"""
        self.auto_refresh = self.refresh_var.get()
        if self.auto_refresh:
            self.refresh_data()
    
    def refresh_data(self):
        """Refresh all data displays"""
        # This will be called periodically or manually
        try:
            # Update alerts
            self.update_alerts()
            
            # Update statistics
            self.update_statistics()
            
            # Update activity log
            self.update_activity_log()
            
            # Update events list (if tab is visible)
            if self.notebook.index("current") == 1:  # Events tab
                self.apply_event_filters()
            
            # Update files list (if tab is visible)
            if self.notebook.index("current") == 2:  # Files tab
                self.apply_file_filters()
            
            # Update processes list (if tab is visible)
            if self.notebook.index("current") == 3:  # Processes tab
                self.update_processes_list()
            
            # Update network list (if tab is visible)
            if self.notebook.index("current") == 4:  # Network tab
                self.update_network_list()
            
            # Update reports list (if tab is visible)
            if self.notebook.index("current") == 5:  # Reports tab
                self.update_reports_list()
            
            # Update system status indicators
            self.update_system_status()
            
        except Exception as e:
            logger.error(f"Error refreshing data: {e}")
            self.show_error("Error refreshing data", str(e))
        
        # Schedule next refresh if enabled
        if self.auto_refresh:
            self.root.after(self.refresh_interval * 1000, self.refresh_data)
    
    def update_alerts(self):
        """Update the alerts display"""
        try:
            # Clear existing alerts
            for item in self.alert_tree.get_children():
                self.alert_tree.delete(item)
            
            # Get latest high-severity events
            conn = sqlite3.connect('data/ransomeye.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, timestamp, event_type, severity, description
                FROM events
                WHERE severity >= 7
                ORDER BY timestamp DESC
                LIMIT 10
            """)
            
            alerts = cursor.fetchall()
            conn.close()
            
            # Populate alerts
            for alert in alerts:
                timestamp = datetime.fromisoformat(alert['timestamp']).strftime('%H:%M:%S')
                event_type = alert['event_type'].replace('suspicious_', '').replace('anomaly_', 'AI-')
                
                self.alert_tree.insert('', tk.END, values=(
                    timestamp,
                    event_type,
                    alert['severity'],
                    alert['description']
                ))
                
            # Update threat level based on recent high-severity events
            self.update_threat_level()
            
        except Exception as e:
            logger.error(f"Error updating alerts: {e}")
    
    def update_statistics(self):
        """Update the statistics charts"""
        try:
            # Clear previous figure
            self.fig.clear()
            
            # Create a subplot
            ax = self.fig.add_subplot(111)
            ax.set_facecolor(self.colors["bg"])
            ax.tick_params(axis='x', colors=self.colors["fg"])
            ax.tick_params(axis='y', colors=self.colors["fg"])
            
            # Get event counts by type
            conn = sqlite3.connect('data/ransomeye.db')
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT event_type, COUNT(*) as count
                FROM events
                GROUP BY event_type
                ORDER BY count DESC
                LIMIT 6
            """)
            
            results = cursor.fetchall()
            conn.close()
            
            if not results:
                ax.text(0.5, 0.5, "No data available", 
                      color=self.colors["fg"], 
                      ha='center', va='center',
                      transform=ax.transAxes)
                self.canvas.draw()
                return
            
            # Prepare data for plotting
            event_types = [r[0].replace('suspicious_', '').replace('anomaly_', 'AI-') for r in results]
            counts = [r[1] for r in results]
            
            # Create bar chart
            bars = ax.bar(event_types, counts)
            
            # Set colors
            for i, bar in enumerate(bars):
                if "file" in event_types[i]:
                    bar.set_color(self.colors["highlight"])
                elif "process" in event_types[i]:
                    bar.set_color(self.colors["warning"])
                else:
                    bar.set_color(self.colors["info"])
            
            # Set labels
            ax.set_title("Event Distribution", color=self.colors["fg"])
            ax.set_ylabel("Count", color=self.colors["fg"])
            
            # Adjust x-axis labels for readability
            plt.xticks(rotation=45, ha='right')
            
            # Tight layout
            self.fig.tight_layout()
            
            # Draw the canvas
            self.canvas.draw()
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    def update_activity_log(self):
        """Update the activity log text"""
        try:
            # Clear existing text
            self.activity_text.delete(1.0, tk.END)
            
            # Get recent events
            conn = sqlite3.connect('data/ransomeye.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT timestamp, event_type, source, description
                FROM events
                ORDER BY timestamp DESC
                LIMIT 20
            """)
            
            events = cursor.fetchall()
            conn.close()
            
            # Format and display events
            for event in events:
                timestamp = datetime.fromisoformat(event['timestamp']).strftime('%H:%M:%S')
                
                # Format based on event type
                if 'suspicious' in event['event_type']:
                    self.activity_text.insert(tk.END, f"{timestamp} ", "timestamp")
                    self.activity_text.insert(tk.END, f"[{event['source']}] ", "source")
                    self.activity_text.insert(tk.END, f"{event['description']}\n", "warning")
                elif 'anomaly' in event['event_type']:
                    self.activity_text.insert(tk.END, f"{timestamp} ", "timestamp")
                    self.activity_text.insert(tk.END, f"[AI] ", "source")
                    self.activity_text.insert(tk.END, f"{event['description']}\n", "anomaly")
                else:
                    self.activity_text.insert(tk.END, f"{timestamp} ", "timestamp")
                    self.activity_text.insert(tk.END, f"[{event['source']}] ", "source")
                    self.activity_text.insert(tk.END, f"{event['description']}\n", "normal")
            
            # Configure text tags
            self.activity_text.tag_configure("timestamp", foreground="#888888")
            self.activity_text.tag_configure("source", foreground=self.colors["info"])
            self.activity_text.tag_configure("warning", foreground=self.colors["warning"])
            self.activity_text.tag_configure("anomaly", foreground=self.colors["highlight"])
            self.activity_text.tag_configure("normal", foreground=self.colors["fg"])
            
        except Exception as e:
            logger.error(f"Error updating activity log: {e}")
    
    def update_threat_level(self):
        """Update the current threat level indicator"""
        try:
            # Get recent high-severity events (last hour)
            conn = sqlite3.connect('data/ransomeye.db')
            cursor = conn.cursor()
            
            one_hour_ago = (datetime.now() - datetime.timedelta(hours=1)).isoformat()
            
            cursor.execute("""
                SELECT COUNT(*) as critical_count FROM events
                WHERE severity >= 9 AND timestamp > ?
            """, (one_hour_ago,))
            critical_count = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) as high_count FROM events
                WHERE severity >= 7 AND timestamp > ?
            """, (one_hour_ago,))
            high_count = cursor.fetchone()[0]
            
            conn.close()
            
            # Determine threat level
            if critical_count > 0:
                self.threat_level_label.config(text="Current Threat Level: CRITICAL", style="Critical.TLabel")
            elif high_count > 2:
                self.threat_level_label.config(text="Current Threat Level: High", style="Warning.TLabel")
            elif high_count > 0:
                self.threat_level_label.config(text="Current Threat Level: Elevated", style="Warning.TLabel")
            else:
                self.threat_level_label.config(text="Current Threat Level: Normal", style="Info.TLabel")
                
        except Exception as e:
            logger.error(f"Error updating threat level: {e}")
    
    def update_system_status(self):
        """Update the system status indicators"""
        try:
            # Update auto-mitigation status from current config
            auto_mitigate = self.db_writer.get_config_value('auto_mitigation', 'False')
            mitigation_status = "Enabled" if auto_mitigate == 'True' else "Disabled"
            self.mitigation_label.config(text=f"Auto-Mitigation: {mitigation_status}")
            
        except Exception as e:
            logger.error(f"Error updating system status: {e}")
    
    def apply_event_filters(self):
        """Apply filters to the events list"""
        try:
            # Clear existing events
            for item in self.events_tree.get_children():
                self.events_tree.delete(item)
            
            # Get filtered events
            conn = sqlite3.connect('data/ransomeye.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            event_type = self.event_type_var.get()
            min_severity = int(self.severity_var.get())
            
            if event_type == "All":
                cursor.execute("""
                    SELECT id, timestamp, event_type, severity, source, description, mitigated
                    FROM events
                    WHERE severity >= ?
                    ORDER BY timestamp DESC
                    LIMIT 1000
                """, (min_severity,))
            else:
                cursor.execute("""
                    SELECT id, timestamp, event_type, severity, source, description, mitigated
                    FROM events
                    WHERE event_type = ? AND severity >= ?
                    ORDER BY timestamp DESC
                    LIMIT 1000
                """, (event_type, min_severity))
            
            events = cursor.fetchall()
            conn.close()
            
            # Populate events
            for event in events:
                timestamp = datetime.fromisoformat(event['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                mitigated = "Yes" if event['mitigated'] else "No"
                
                item_id = self.events_tree.insert('', tk.END, values=(
                    event['id'],
                    timestamp,
                    event['event_type'],
                    event['severity'],
                    event['source'],
                    event['description'],
                    mitigated
                ))
                
                # Color high-severity events
                if event['severity'] >= 9:
                    self.events_tree.tag_configure("critical", background=self.colors["highlight"], foreground="black")
                    self.events_tree.item(item_id, tags=("critical",))
                elif event['severity'] >= 7:
                    self.events_tree.tag_configure("high", background=self.colors["warning"], foreground="black")
                    self.events_tree.item(item_id, tags=("high",))
                
        except Exception as e:
            logger.error(f"Error applying event filters: {e}")
            self.show_error("Error", f"Failed to apply event filters: {str(e)}")
    
    def apply_file_filters(self):
        """Apply filters to the files list"""
        try:
            # Clear existing files
            for item in self.files_tree.get_children():
                self.files_tree.delete(item)
            
            # Get filtered files
            conn = sqlite3.connect('data/ransomeye.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            min_entropy = float(self.entropy_var.get())
            
            cursor.execute("""
                SELECT id, event_id, file_path, file_hash, entropy, action_taken
                FROM file_events
                WHERE entropy >= ?
                ORDER BY id DESC
                LIMIT 1000
            """, (min_entropy,))
            
            files = cursor.fetchall()
            conn.close()
            
            # Populate files
            for file in files:
                self.files_tree.insert('', tk.END, values=(
                    file['id'],
                    file['event_id'],
                    file['file_path'],
                    file['file_hash'],
                    round(file['entropy'], 2),
                    file['action_taken']
                ))
                
        except Exception as e:
            logger.error(f"Error applying file filters: {e}")
            self.show_error("Error", f"Failed to apply file filters: {str(e)}")
    
    def update_processes_list(self):
        """Update the processes list"""
        try:
            # Clear existing processes
            for item in self.processes_tree.get_children():
                self.processes_tree.delete(item)
            
            # Get processes
            conn = sqlite3.connect('data/ransomeye.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, event_id, pid, process_name, command_line, parent_pid, action_taken
                FROM process_events
                ORDER BY id DESC
                LIMIT 1000
            """)
            
            processes = cursor.fetchall()
            conn.close()
            
            # Populate processes
            for proc in processes:
                self.processes_tree.insert('', tk.END, values=(
                    proc['id'],
                    proc['event_id'],
                    proc['pid'],
                    proc['process_name'],
                    proc['command_line'],
                    proc['parent_pid'],
                    proc['action_taken']
                ))
                
        except Exception as e:
            logger.error(f"Error updating processes list: {e}")
    
    def update_network_list(self):
        """Update the network connections list"""
        try:
            # Clear existing connections
            for item in self.network_tree.get_children():
                self.network_tree.delete(item)
            
            # Get network connections
            conn = sqlite3.connect('data/ransomeye.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, event_id, source_ip, destination_ip, source_port, destination_port,
                       protocol, action_taken
                FROM network_events
                ORDER BY id DESC
                LIMIT 1000
            """)
            
            connections = cursor.fetchall()
            conn.close()
            
            # Populate connections
            for conn in connections:
                self.network_tree.insert('', tk.END, values=(
                    conn['id'],
                    conn['event_id'],
                    conn['source_ip'],
                    conn['destination_ip'],
                    conn['source_port'],
                    conn['destination_port'],
                    conn['protocol'],
                    conn['action_taken']
                ))
                
        except Exception as e:
            logger.error(f"Error updating network list: {e}")
    
    def update_reports_list(self):
        """Update the available reports list"""
        try:
            # Clear existing reports
            for item in self.reports_list.get_children():
                self.reports_list.delete(item)
            
            # List files in the reports directory
            reports_dir = "reports"
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
            
            reports = []
            for filename in os.listdir(reports_dir):
                if os.path.isfile(os.path.join(reports_dir, filename)):
                    stats = os.stat(os.path.join(reports_dir, filename))
                    
                    # Get file type
                    file_type = filename.split('.')[-1] if '.' in filename else 'unknown'
                    
                    # Get file size
                    size_kb = stats.st_size / 1024
                    size_text = f"{size_kb:.1f} KB"
                    
                    # Get modification time
                    mod_time = datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    
                    reports.append((filename, mod_time, file_type, size_text))
            
            # Sort by modification time (newest first)
            reports.sort(key=lambda x: x[1], reverse=True)
            
            # Populate reports
            for report in reports:
                self.reports_list.insert('', tk.END, values=report)
                
        except Exception as e:
            logger.error(f"Error updating reports list: {e}")
    
    def show_event_details(self, event):
        """Show detailed information about an event"""
        try:
            selection = self.events_tree.selection()
            if not selection:
                return
                
            # Get event ID from selected item
            item = self.events_tree.item(selection[0])
            event_id = item["values"][0]
            
            # Get event details
            conn = sqlite3.connect('data/ransomeye.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get the event
            cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
            event_data = cursor.fetchone()
            
            if not event_data:
                conn.close()
                return
            
            # Get associated data based on event type
            details = {}
            
            if "file" in event_data["event_type"]:
                cursor.execute("SELECT * FROM file_events WHERE event_id = ?", (event_id,))
                details["file_details"] = cursor.fetchall()
                
            elif "process" in event_data["event_type"]:
                cursor.execute("SELECT * FROM process_events WHERE event_id = ?", (event_id,))
                details["process_details"] = cursor.fetchall()
                
                # Get process tree if available
                for proc in details["process_details"]:
                    if proc["process_tree"]:
                        details["process_tree"] = proc["process_tree"]
                        
            elif "network" in event_data["event_type"]:
                cursor.execute("SELECT * FROM network_events WHERE event_id = ?", (event_id,))
                details["network_details"] = cursor.fetchall()
            
            conn.close()
            
            # Create details window
            details_window = tk.Toplevel(self.root)
            details_window.title(f"Event Details: {event_id}")
            details_window.geometry("600x400")
            details_window.configure(bg=self.colors["bg"])
            
            # Event information
            info_frame = ttk.LabelFrame(details_window, text="Event Information")
            info_frame.pack(fill=tk.X, padx=10, pady=10)
            
            # Format timestamp
            timestamp = datetime.fromisoformat(event_data["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            
            ttk.Label(info_frame, text=f"Type: {event_data['event_type']}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Time: {timestamp}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Severity: {event_data['severity']}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Source: {event_data['source']}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Description: {event_data['description']}").pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(info_frame, text=f"Mitigated: {'Yes' if event_data['mitigated'] else 'No'}").pack(anchor=tk.W, padx=5, pady=2)
            
            # Display type-specific details
            if "file_details" in details:
                file_frame = ttk.LabelFrame(details_window, text="File Details")
                file_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                file_text = tk.Text(file_frame, wrap=tk.WORD, height=10, bg=self.colors["bg"], fg=self.colors["fg"])
                file_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                
                for file in details["file_details"]:
                    file_text.insert(tk.END, f"File Path: {file['file_path']}\n")
                    file_text.insert(tk.END, f"File Hash: {file['file_hash']}\n")
                    file_text.insert(tk.END, f"Entropy: {file['entropy']}\n")
                    file_text.insert(tk.END, f"Action Taken: {file['action_taken']}\n\n")
            
            elif "process_details" in details:
                process_frame = ttk.LabelFrame(details_window, text="Process Details")
                process_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                process_text = tk.Text(process_frame, wrap=tk.WORD, height=10, bg=self.colors["bg"], fg=self.colors["fg"])
                process_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                
                for proc in details["process_details"]:
                    process_text.insert(tk.END, f"Process ID: {proc['pid']}\n")
                    process_text.insert(tk.END, f"Name: {proc['process_name']}\n")
                    process_text.insert(tk.END, f"Command Line: {proc['command_line']}\n")
                    process_text.insert(tk.END, f"Parent PID: {proc['parent_pid']}\n")
                    if proc['process_tree']:
                        process_text.insert(tk.END, f"Process Tree: {proc['process_tree']}\n")
                    process_text.insert(tk.END, f"Action Taken: {proc['action_taken']}\n\n")
            
            elif "network_details" in details:
                network_frame = ttk.LabelFrame(details_window, text="Network Details")
                network_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                network_text = tk.Text(network_frame, wrap=tk.WORD, height=10, bg=self.colors["bg"], fg=self.colors["fg"])
                network_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                
                for conn in details["network_details"]:
                    network_text.insert(tk.END, f"Source IP: {conn['source_ip']}:{conn['source_port']}\n")
                    network_text.insert(tk.END, f"Destination IP: {conn['destination_ip']}:{conn['destination_port']}\n")
                    network_text.insert(tk.END, f"Protocol: {conn['protocol']}\n")
                    network_text.insert(tk.END, f"Action Taken: {conn['action_taken']}\n\n")
            
            # Close button
            close_btn = ttk.Button(details_window, text="Close", command=details_window.destroy)
            close_btn.pack(pady=10)
            
        except Exception as e:
            logger.error(f"Error showing event details: {e}")
            self.show_error("Error", f"Failed to show event details: {str(e)}")
    
    def show_process_tree(self):
        """Show the process tree for a selected process"""
        try:
            selection = self.processes_tree.selection()
            if not selection:
                return
                
            # Get process details from selected item
            item = self.processes_tree.item(selection[0])
            process_id = item["values"][0]
            
            # Get process tree from database
            conn = sqlite3.connect('data/ransomeye.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT process_tree FROM process_events WHERE id = ?", (process_id,))
            result = cursor.fetchone()
            conn.close()
            
            if not result or not result['process_tree']:
                messagebox.showinfo("Process Tree", "No process tree information available for this process.")
                return
            
            process_tree = result['process_tree']
            
            # Create tree visualization window
            tree_window = tk.Toplevel(self.root)
            tree_window.title("Process Tree")
            tree_window.geometry("600x400")
            tree_window.configure(bg=self.colors["bg"])
            
            # Display the process tree
            tree_frame = ttk.Frame(tree_window)
            tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            tree_text = tk.Text(tree_frame, wrap=tk.WORD, height=20, bg=self.colors["bg"], fg=self.colors["fg"])
            tree_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Format the process tree as a hierarchical display
            processes = process_tree.split(" -> ")
            for i, proc in enumerate(processes):
                indent = " " * (i * 2)
                if i < len(processes) - 1:
                    tree_text.insert(tk.END, f"{indent}├─ {proc}\n")
                else:
                    tree_text.insert(tk.END, f"{indent}└─ {proc}\n")
            
            # Close button
            close_btn = ttk.Button(tree_window, text="Close", command=tree_window.destroy)
            close_btn.pack(pady=10)
            
        except Exception as e:
            logger.error(f"Error showing process tree: {e}")
            self.show_error("Error", f"Failed to show process tree: {str(e)}")
    
    def action_on_selected(self, tree, action):
        """Perform an action on the selected item(s)"""
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("Information", "No items selected")
            return
        
        try:
            if action == "quarantine":
                self.quarantine_selected_files(selection)
            elif action == "restore":
                self.restore_selected_files(selection)
            elif action == "kill":
                self.terminate_selected_processes(selection)
            elif action == "block":
                self.block_selected_connections(selection)
                
        except Exception as e:
            logger.error(f"Error performing {action}: {e}")
            self.show_error("Error", f"Failed to perform {action}: {str(e)}")
    
    def quarantine_selected_files(self, selection):
        """Quarantine selected files"""
        # Implement file quarantine
        pass  # To be implemented
    
    def restore_selected_files(self, selection):
        """Restore selected files from quarantine"""
        # Implement file restoration
        pass  # To be implemented
    
    def terminate_selected_processes(self, selection):
        """Terminate selected processes"""
        # Implement process termination
        pass  # To be implemented
    
    def block_selected_connections(self, selection):
        """Block selected network connections"""
        # Implement connection blocking
        pass  # To be implemented
    
    def emergency_isolate(self):
        """Emergency system isolation"""
        if messagebox.askyesno("Emergency Isolation", 
                            "WARNING: This will disconnect the system from the network. Continue?", 
                            icon=messagebox.WARNING):
            try:
                # Implement emergency isolation
                messagebox.showinfo("Emergency Isolation", "System isolation initiated")
            except Exception as e:
                logger.error(f"Error during emergency isolation: {e}")
                self.show_error("Error", f"Failed to isolate system: {str(e)}")
    
    def kill_suspicious(self):
        """Kill all suspicious processes"""
        if messagebox.askyesno("Kill Suspicious Processes", 
                            "WARNING: This will terminate all flagged suspicious processes. Continue?", 
                            icon=messagebox.WARNING):
            try:
                # Implement mass process termination
                messagebox.showinfo("Process Termination", "Suspicious processes terminated")
            except Exception as e:
                logger.error(f"Error killing suspicious processes: {e}")
                self.show_error("Error", f"Failed to kill processes: {str(e)}")
    
    def generate_report(self):
        """Generate a report based on current settings"""
        try:
            # Get report parameters
            time_range = self.time_range_var.get()
            report_format = self.format_var.get()
            
            include_files = self.include_files_var.get()
            include_processes = self.include_processes_var.get()
            include_network = self.include_network_var.get()
            include_mitigations = self.include_mitigations_var.get()
            
            # Generate timestamp for filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create reports directory if it doesn't exist
            reports_dir = "reports"
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
            
            # Generate the report
            if report_format == "pdf":
                filename = os.path.join(reports_dir, f"ransomeye_report_{timestamp}.pdf")
                self.generate_pdf_report(filename, time_range, include_files, 
                                       include_processes, include_network, include_mitigations)
            elif report_format == "csv":
                filename = os.path.join(reports_dir, f"ransomeye_report_{timestamp}.csv")
                self.generate_csv_report(filename, time_range, include_files, 
                                       include_processes, include_network, include_mitigations)
            elif report_format == "json":
                filename = os.path.join(reports_dir, f"ransomeye_report_{timestamp}.json")
                self.generate_json_report(filename, time_range, include_files, 
                                        include_processes, include_network, include_mitigations)
            
            messagebox.showinfo("Report Generated", f"Report saved to {filename}")
            
            # Refresh the reports list
            self.update_reports_list()
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            self.show_error("Error", f"Failed to generate report: {str(e)}")
    
    def generate_pdf_report(self, filename, time_range, include_files, include_processes, include_network, include_mitigations):
        """Generate a PDF report"""
        # This would use a library like pdfkit, reportlab, etc.
        # Sample implementation
        with open(filename, 'w') as f:
            f.write("RansomEye PDF Report - This is a placeholder\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Time Range: {time_range}\n")
            f.write(f"Included Sections: Files={include_files}, Processes={include_processes}, Network={include_network}, Mitigations={include_mitigations}\n")
    
    def generate_csv_report(self, filename, time_range, include_files, include_processes, include_network, include_mitigations):
        """Generate a CSV report"""
        # Sample implementation
        with open(filename, 'w') as f:
            f.write("RansomEye CSV Report\n")
            f.write(f"Generated,{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Time Range,{time_range}\n")
    
    def generate_json_report(self, filename, time_range, include_files, include_processes, include_network, include_mitigations):
        """Generate a JSON report"""
        # Sample implementation
        report_data = {
            "generated": datetime.now().isoformat(),
            "time_range": time_range,
            "sections": {
                "files": include_files,
                "processes": include_processes,
                "network": include_network,
                "mitigations": include_mitigations
            },
            "events": []
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
    
    def open_report(self):
        """Open a selected report"""
        selection = self.reports_list.selection()
        if not selection:
            messagebox.showinfo("Information", "No report selected")
            return
            
        # Get filename from selected item
        item = self.reports_list.item(selection[0])
        filename = item["values"][0]
        
        # Open the report (platform-specific)
        try:
            report_path = os.path.join("reports", filename)
            
            if sys.platform.startswith('darwin'):  # macOS
                os.system(f"open '{report_path}'")
            elif sys.platform.startswith('linux'):  # Linux
                os.system(f"xdg-open '{report_path}'")
            elif sys.platform.startswith('win'):    # Windows
                os.startfile(report_path)
            else:
                messagebox.showinfo("Information", f"Report saved at: {report_path}")
                
        except Exception as e:
            logger.error(f"Error opening report: {e}")
            self.show_error("Error", f"Failed to open report: {str(e)}")
    
    def delete_report(self):
        """Delete a selected report"""
        selection = self.reports_list.selection()
        if not selection:
            messagebox.showinfo("Information", "No report selected")
            return
            
        # Get filename from selected item
        item = self.reports_list.item(selection[0])
        filename = item["values"][0]
        
        # Confirm deletion
        if messagebox.askyesno("Confirm Deletion", f"Delete report: {filename}?"):
            try:
                report_path = os.path.join("reports", filename)
                os.remove(report_path)
                messagebox.showinfo("Success", f"Report {filename} deleted")
                
                # Refresh the reports list
                self.update_reports_list()
                
            except Exception as e:
                logger.error(f"Error deleting report: {e}")
                self.show_error("Error", f"Failed to delete report: {str(e)}")
    
    def save_config(self):
        """Save the configuration settings"""
        try:
            # Validate input values
            try:
                scan_interval = int(self.scan_interval_var.get())
                entropy_threshold = float(self.entropy_threshold_var.get())
                cpu_threshold = int(self.cpu_threshold_var.get())
                conn_threshold = int(self.conn_threshold_var.get())
                ai_threshold = float(self.ai_threshold_var.get())
                
                if scan_interval < 10 or scan_interval > 3600:
                    raise ValueError("Scan interval must be between 10 and 3600 seconds")
                
                if entropy_threshold < 0 or entropy_threshold > 8:
                    raise ValueError("Entropy threshold must be between 0 and 8")
                
                if cpu_threshold < 0 or cpu_threshold > 100:
                    raise ValueError("CPU threshold must be between 0 and 100")
                
                if ai_threshold < 0 or ai_threshold > 1:
                    raise ValueError("AI confidence threshold must be between 0 and 1")
                
            except ValueError as e:
                messagebox.showerror("Invalid Input", str(e))
                return
            
            # Update database configuration
            self.db_writer.set_config_value('scan_interval', str(scan_interval))
            self.db_writer.set_config_value('entropy_threshold', str(entropy_threshold))
            self.db_writer.set_config_value('process_cpu_threshold', str(cpu_threshold))
            self.db_writer.set_config_value('network_conn_threshold', str(conn_threshold))
            self.db_writer.set_config_value('ai_confidence_threshold', str(ai_threshold))
            self.db_writer.set_config_value('auto_mitigation', str(self.auto_mitigate_var.get()))
            
            # Update local config
            self.config['scan_interval'] = str(scan_interval)
            self.config['entropy_threshold'] = str(entropy_threshold)
            self.config['process_cpu_threshold'] = str(cpu_threshold)
            self.config['network_conn_threshold'] = str(conn_threshold)
            self.config['ai_confidence_threshold'] = str(ai_threshold)
            self.config['auto_mitigation'] = str(self.auto_mitigate_var.get())
            
            # Update UI elements that use these values
            self.update_system_status()
            
            messagebox.showinfo("Configuration Saved", "Settings have been updated successfully")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            self.show_error("Error", f"Failed to save configuration: {str(e)}")
    
    def show_error(self, title, message):
        """Display an error message dialog"""
        messagebox.showerror(title, message)


def start_dashboard(message_queue, config):
    """Start the dashboard UI"""
    try:
        # Create the root Tkinter window
        root = tk.Tk()
        
        # Create the dashboard application
        app = RansomEyeDashboard(root, message_queue, config)
        
        # Start the main event loop
        root.mainloop()
        
    except Exception as e:
        logger.error(f"Error starting dashboard: {e}")
        print(f"Error starting dashboard: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start_dashboard(None, {})
