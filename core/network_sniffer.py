
#!/usr/bin/env python3
# Network Sniffer Module for RansomEye

import os
import time
import logging
import threading
import ipaddress
import socket
import scapy.all as scapy
from collections import defaultdict

logger = logging.getLogger("RansomEye.NetworkSniffer")

class NetworkSniffer:
    # Suspicious port numbers
    SUSPICIOUS_PORTS = {
        # Common C2 and backdoor ports
        4444, 4445, 1234, 6666, 6667, 6668, 6669, 
        # Common ransomware ports
        8080, 8081, 9001, 9050, 8333, 8888, 
        # TOR ports
        9050, 9051,
        # IRC ports (often used for C2)
        6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669,
        # Others
        31337, 12345, 54321
    }
    
    # Known malicious IP address patterns (start with these)
    # In a real implementation, would use threat intelligence feeds
    SUSPICIOUS_IP_PATTERNS = [
        "192.42.116.", "195.123.246.", "185.130.44.",
        "94.142.138.", "94.23.", "31.184.", "200.7.105.",
        "146.0.72.", "194.87.218."
    ]
    
    def __init__(self, db_writer, anomaly_engine, mitigation, conn_threshold=50):
        self.db_writer = db_writer
        self.anomaly_engine = anomaly_engine
        self.mitigation = mitigation
        self.conn_threshold = conn_threshold
        self.packet_buffer = []
        self.connections = defaultdict(int)  # track connection attempts
        self.suspicious_conns = set()  # track already reported suspicious connections
        
    def start_monitoring(self):
        """Start monitoring network traffic"""
        try:
            logger.info("Network sniffer started")
            
            # Start packet capture in a separate thread
            capture_thread = threading.Thread(target=self.capture_packets)
            capture_thread.daemon = True
            capture_thread.start()
            
            # Analysis loop in main thread
            while True:
                self.analyze_packet_buffer()
                self.check_connection_patterns()
                time.sleep(2)  # Analyze every 2 seconds
                
        except Exception as e:
            logger.error(f"Error in network monitoring: {e}")
    
    def capture_packets(self):
        """Capture network packets using Scapy"""
        try:
            # Set a high timeout to avoid issues on busy networks
            scapy.conf.sniff_timeout = 1  # 1 second timeout
            
            # Start packet sniffing (non-blocking)
            scapy.sniff(prn=self.process_packet, store=False, filter="ip")
            
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
    
    def process_packet(self, packet):
        """Process each captured packet"""
        try:
            # Add packet to buffer for later analysis
            # Only keep the last 1000 packets to avoid memory issues
            self.packet_buffer.append(packet)
            if len(self.packet_buffer) > 1000:
                self.packet_buffer.pop(0)
                
            # Quick check for suspicious ports
            if scapy.TCP in packet and (packet[scapy.TCP].dport in self.SUSPICIOUS_PORTS or 
                                      packet[scapy.TCP].sport in self.SUSPICIOUS_PORTS):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                
                conn_tuple = (src_ip, dst_ip, src_port, dst_port)
                if conn_tuple not in self.suspicious_conns:
                    self.record_suspicious_connection(src_ip, dst_ip, src_port, dst_port,
                                                    "Suspicious port detected")
                    self.suspicious_conns.add(conn_tuple)
            
            # Track connection attempts for connection flood detection
            if scapy.TCP in packet and packet[scapy.TCP].flags & 0x02:  # SYN flag
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                self.connections[(src_ip, dst_ip)] += 1
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def analyze_packet_buffer(self):
        """Analyze the buffered packets for suspicious patterns"""
        if not self.packet_buffer:
            return
            
        try:
            # Look for patterns in the packet buffer
            ip_counts = defaultdict(int)
            port_counts = defaultdict(int)
            
            for packet in self.packet_buffer:
                if scapy.IP in packet:
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    
                    ip_counts[src_ip] += 1
                    ip_counts[dst_ip] += 1
                    
                    # Check for suspicious IP patterns
                    for pattern in self.SUSPICIOUS_IP_PATTERNS:
                        if dst_ip.startswith(pattern) or src_ip.startswith(pattern):
                            src_port = packet[scapy.TCP].sport if scapy.TCP in packet else 0
                            dst_port = packet[scapy.TCP].dport if scapy.TCP in packet else 0
                            
                            conn_tuple = (src_ip, dst_ip, src_port, dst_port)
                            if conn_tuple not in self.suspicious_conns:
                                self.record_suspicious_connection(src_ip, dst_ip, src_port, dst_port,
                                                               "Connection to suspicious IP")
                                self.suspicious_conns.add(conn_tuple)
                    
                    # Track ports for suspicious port scanning
                    if scapy.TCP in packet:
                        src_port = packet[scapy.TCP].sport
                        dst_port = packet[scapy.TCP].dport
                        port_counts[(dst_ip, dst_port)] += 1
            
            # Clear buffer after analysis
            self.packet_buffer = []
            
        except Exception as e:
            logger.error(f"Error analyzing packet buffer: {e}")
    
    def check_connection_patterns(self):
        """Check for suspicious connection patterns"""
        try:
            # Check for connection floods (potential scanning/brute force)
            for (src_ip, dst_ip), count in self.connections.items():
                if count > self.conn_threshold:
                    conn_tuple = (src_ip, dst_ip, 0, 0)  # Using 0 for ports as we don't know them here
                    if conn_tuple not in self.suspicious_conns:
                        self.record_suspicious_connection(src_ip, dst_ip, 0, 0,
                                                       f"Connection flood detected ({count} attempts)")
                        self.suspicious_conns.add(conn_tuple)
            
            # Reset connection counter periodically
            self.connections = defaultdict(int)
            
        except Exception as e:
            logger.error(f"Error checking connection patterns: {e}")
    
    def record_suspicious_connection(self, src_ip, dst_ip, src_port, dst_port, reason):
        """Record a suspicious network connection"""
        try:
            logger.warning(f"Suspicious network activity detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port} - {reason}")
            
            # Try to get hostname information
            try:
                src_host = socket.gethostbyaddr(src_ip)[0]
            except:
                src_host = "unknown"
                
            try:
                dst_host = socket.gethostbyaddr(dst_ip)[0]
            except:
                dst_host = "unknown"
            
            # Determine if internal or external
            is_internal_src = self.is_private_ip(src_ip)
            is_internal_dst = self.is_private_ip(dst_ip)
            
            # Determine severity based on the reason and internal/external status
            severity = 6
            protocol = "TCP"
            
            if "Suspicious port" in reason:
                severity = 7
            elif "Connection to suspicious IP" in reason:
                severity = 8
            elif "Connection flood" in reason:
                severity = 8
                
            # External targets are more suspicious
            if not is_internal_dst:
                severity += 1
            
            # Insert event into database
            event_id = self.db_writer.add_event(
                event_type="suspicious_network",
                severity=severity,
                source="network_sniffer",
                description=f"Suspicious network activity: {reason}"
            )
            
            # Record network details
            self.db_writer.add_network_event(
                event_id=event_id,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                packet_count=1,
                action_taken="detected"
            )
            
            # Send to anomaly engine for further analysis
            self.anomaly_engine.analyze_network(src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Consider mitigation for high-severity events
            if severity >= 8:
                self.mitigation.handle_network_threat(src_ip, dst_ip, src_port, dst_port, event_id)
                
        except Exception as e:
            logger.error(f"Error recording suspicious connection: {e}")
    
    def is_private_ip(self, ip):
        """Check if an IP address is private/internal"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
