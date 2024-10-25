import scapy.all as scapy
from scapy.layers import http
import json
import argparse
import sqlite3
from datetime import datetime
import pandas as pd
from typing import Dict, List, Any
import plotly.express as px
import plotly.graph_objects as go
from collections import defaultdict
import threading
import queue
import time

class NetworkAnalyzer:
    def __init__(self, interface: str, db_path: str = "network_analysis.db"):
        self.interface = interface
        self.db_path = db_path
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'ip_sources': defaultdict(int),
            'ip_destinations': defaultdict(int),
            'ports': defaultdict(int),
            'http_requests': [],
            'suspicious_activities': []
        }
        self.initialize_database()

    def initialize_database(self) -> None:
        """Initialize SQLite database for storing packet data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                length INTEGER,
                info TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS http_requests (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                method TEXT,
                host TEXT,
                path TEXT,
                user_agent TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def packet_callback(self, packet: scapy.Packet) -> None:
        """Process captured packets"""
        self.packet_queue.put(packet)
        
    def process_packets(self) -> None:
        """Process packets from queue"""
        while not self.stop_capture.is_set() or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self.analyze_packet(packet)
            except queue.Empty:
                continue

    def analyze_packet(self, packet: scapy.Packet) -> None:
        """Analyze individual packets"""
        self.stats['total_packets'] += 1
        
        # Extract basic packet information
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'length': len(packet),
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'info': ''
        }

        # IP layer analysis
        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP]
            packet_info['src_ip'] = ip.src
            packet_info['dst_ip'] = ip.dst
            self.stats['ip_sources'][ip.src] += 1
            self.stats['ip_destinations'][ip.dst] += 1
            
            # Protocol analysis
            if packet.haslayer(scapy.TCP):
                packet_info['protocol'] = 'TCP'
                tcp = packet[scapy.TCP]
                self.stats['ports'][tcp.dport] += 1
                
                # HTTP analysis
                if packet.haslayer(http.HTTPRequest):
                    self.analyze_http_request(packet, packet_info['timestamp'])
                    
            elif packet.haslayer(scapy.UDP):
                packet_info['protocol'] = 'UDP'
                self.stats['protocols']['UDP'] += 1
                
            elif packet.haslayer(scapy.ICMP):
                packet_info['protocol'] = 'ICMP'
                self.stats['protocols']['ICMP'] += 1

        # Save packet to database
        self.save_packet_to_db(packet_info)
        
        # Check for suspicious activities
        self.detect_anomalies(packet_info)

    def analyze_http_request(self, packet: scapy.Packet, timestamp: str) -> None:
        """Analyze HTTP requests"""
        http_layer = packet[http.HTTPRequest]
        request_info = {
            'timestamp': timestamp,
            'method': http_layer.Method.decode() if http_layer.Method else '',
            'host': http_layer.Host.decode() if http_layer.Host else '',
            'path': http_layer.Path.decode() if http_layer.Path else '',
            'user_agent': http_layer.User_Agent.decode() if http_layer.User_Agent else ''
        }
        
        self.stats['http_requests'].append(request_info)
        self.save_http_request_to_db(request_info)

    def save_packet_to_db(self, packet_info: Dict[str, Any]) -> None:
        """Save packet information to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, info)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            packet_info['timestamp'],
            packet_info['src_ip'],
            packet_info['dst_ip'],
            packet_info['protocol'],
            packet_info['length'],
            packet_info['info']
        ))
        
        conn.commit()
        conn.close()

    def save_http_request_to_db(self, request_info: Dict[str, str]) -> None:
        """Save HTTP request information to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO http_requests (timestamp, method, host, path, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            request_info['timestamp'],
            request_info['method'],
            request_info['host'],
            request_info['path'],
            request_info['user_agent']
        ))
        
        conn.commit()
        conn.close()

    def detect_anomalies(self, packet_info: Dict[str, Any]) -> None:
        """Detect suspicious network activities"""
        # Check for potential port scanning
        if len(self.stats['ports']) > 100:
            self.stats['suspicious_activities'].append({
                'type': 'port_scan',
                'source': packet_info['src_ip'],
                'timestamp': packet_info['timestamp']
            })
        
        # Check for potential DoS attacks
        if self.stats['ip_sources'][packet_info['src_ip']] > 1000:
            self.stats['suspicious_activities'].append({
                'type': 'potential_dos',
                'source': packet_info['src_ip'],
                'timestamp': packet_info['timestamp']
            })

    def generate_report(self) -> Dict[str, Any]:
        """Generate analysis report"""
        conn = sqlite3.connect(self.db_path)
        
        # Load data into pandas
        packets_df = pd.read_sql_query("SELECT * FROM packets", conn)
        http_df = pd.read_sql_query("SELECT * FROM http_requests", conn)
        
        # Create visualizations
        protocol_fig = px.pie(
            values=list(self.stats['protocols'].values()),
            names=list(self.stats['protocols'].keys()),
            title="Protocol Distribution"
        )
        
        traffic_timeline = px.line(
            packets_df,
            x='timestamp',
            y=packets_df.groupby('timestamp').size(),
            title="Traffic Timeline"
        )
        
        # Generate report
        report = {
            'summary': {
                'total_packets': self.stats['total_packets'],
                'unique_sources': len(self.stats['ip_sources']),
                'unique_destinations': len(self.stats['ip_destinations']),
                'http_requests': len(self.stats['http_requests']),
                'suspicious_activities': len(self.stats['suspicious_activities'])
            },
            'top_sources': dict(sorted(
                self.stats['ip_sources'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'protocol_distribution': self.stats['protocols'],
            'suspicious_activities': self.stats['suspicious_activities'],
            'visualizations': {
                'protocol_distribution': protocol_fig.to_json(),
                'traffic_timeline': traffic_timeline.to_json()
            }
        }
        
        conn.close()
        return report

    def start_capture(self, duration: int = None) -> None:
        """Start packet capture"""
        print(f"[*] Starting capture on interface {self.interface}")
        
        # Start processing thread
        process_thread = threading.Thread(target=self.process_packets)
        process_thread.start()
        
        # Start packet capture
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                timeout=duration
            )
        except KeyboardInterrupt:
            print("\n[*] Stopping capture...")
        finally:
            self.stop_capture.set()
            process_thread.join()
            
        print("[+] Capture complete")
        
    def save_report(self, report: Dict[str, Any], filename: str) -> None:
        """Save analysis report to file"""
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"[+] Report saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('interface', help='Network interface to capture')
    parser.add_argument('--duration', type=int, help='Capture duration in seconds')
    args = parser.parse_args()

    analyzer = NetworkAnalyzer(args.interface)
    
    try:
        analyzer.start_capture(args.duration)
        report = analyzer.generate_report()
        
        # Save report
        filename = f"network_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        analyzer.save_report(report, filename)
        
        # Print summary
        print("\n=== Analysis Summary ===")
        print(f"Total Packets: {report['summary']['total_packets']}")
        print(f"Unique Sources: {report['summary']['unique_sources']}")
        print(f"HTTP Requests: {report['summary']['http_requests']}")
        print(f"Suspicious Activities: {report['summary']['suspicious_activities']}")
        
    except Exception as e:
        print(f"[!] Error: {str(e)}")

if __name__ == "__main__":
    main()
