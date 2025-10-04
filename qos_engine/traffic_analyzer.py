"""
Traffic Analyzer Module
Real-time network traffic analysis and classification
"""
import time
import json
import logging
import statistics
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
import psutil
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from threading import Thread, Event, Lock
import numpy as np

logger = logging.getLogger(__name__)

@dataclass
class TrafficFlow:
    """Represents a network traffic flow"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    first_seen: datetime = None
    last_seen: datetime = None
    application: str = "unknown"
    priority: str = "normal"
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.last_seen is None:
            self.last_seen = datetime.now()

@dataclass
class TrafficStats:
    """Traffic statistics for a time period"""
    timestamp: datetime
    total_bytes: int
    total_packets: int
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
    http_traffic: int
    https_traffic: int
    ssh_traffic: int
    ftp_traffic: int
    dns_traffic: int
    top_talkers: List[Dict]
    protocol_distribution: Dict[str, int]
    bandwidth_utilization: float

class ApplicationClassifier:
    """Classify network traffic by application type"""
    
    # Port-to-application mapping
    PORT_MAPPING = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB"
    }
    
    # Deep packet inspection patterns
    DPI_PATTERNS = {
        "HTTP": [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HTTP/"],
        "HTTPS": [b"\x16\x03\x01", b"\x16\x03\x02", b"\x16\x03\x03"],
        "SSH": [b"SSH-2.0", b"SSH-1.99"],
        "FTP": [b"220 ", b"USER ", b"PASS "],
        "SMTP": [b"HELO ", b"EHLO ", b"MAIL FROM:"],
        "POP3": [b"+OK ", b"USER ", b"PASS "],
        "IMAP": [b"* OK ", b"A001 "],
        "DNS": [b"\x00\x01\x00\x00", b"\x00\x01\x00\x01"],
        "BitTorrent": [b"\x13BitTorrent protocol", b"announce"],
        "Skype": [b"SRTP", b"RTP/"],
        "WhatsApp": [b"WA", b"WhatsApp"],
        "YouTube": [b"youtube.com", b"googlevideo.com"],
        "Netflix": [b"netflix.com", b"nflxvideo.net"]
    }
    
    @classmethod
    def classify_by_port(cls, port: int) -> str:
        """Classify application by port number"""
        return cls.PORT_MAPPING.get(port, "unknown")
    
    @classmethod
    def classify_by_payload(cls, payload: bytes) -> str:
        """Classify application by payload inspection"""
        if not payload:
            return "unknown"
        
        for app, patterns in cls.DPI_PATTERNS.items():
            for pattern in patterns:
                if pattern in payload[:200]:  # Check first 200 bytes
                    return app
        return "unknown"
    
    @classmethod
    def classify_flow(cls, src_port: int, dst_port: int, payload: bytes = b"") -> str:
        """Comprehensive flow classification"""
        # Try port-based classification first
        app_src = cls.classify_by_port(src_port)
        app_dst = cls.classify_by_port(dst_port)
        
        if app_src != "unknown":
            return app_src
        if app_dst != "unknown":
            return app_dst
        
        # Try payload-based classification
        return cls.classify_by_payload(payload)

class TrafficAnalyzer:
    """Real-time network traffic analyzer"""
    
    def __init__(self, interface: Optional[str] = None, capture_filter: str = ""):
        self.interface = interface
        self.capture_filter = capture_filter
        self.flows: Dict[str, TrafficFlow] = {}
        self.stats_history: deque = deque(maxlen=1000)  # Keep last 1000 stats
        self.is_running = False
        self._stop_event = Event()
        self._capture_thread = None
        self._stats_lock = Lock()
        self._flow_lock = Lock()
        
        # Performance counters
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = None
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def _get_flow_key(self, src_ip: str, dst_ip: str, src_port: int, 
                     dst_port: int, protocol: str) -> str:
        """Generate unique flow identifier"""
        # Normalize flow direction for bidirectional flows
        if (src_ip, src_port) > (dst_ip, dst_port):
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    
    def _packet_handler(self, packet):
        """Handle captured packets"""
        try:
            self.packet_count += 1
            
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = "IP"
                src_port = dst_port = 0
                payload = b""
                
                # Extract transport layer info
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = "TCP"
                    payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = "UDP"
                    payload = bytes(udp_layer.payload) if udp_layer.payload else b""
                
                # Update flow information
                self._update_flow(src_ip, dst_ip, src_port, dst_port, 
                                protocol, len(packet), payload)
                
                self.byte_count += len(packet)
            
            elif IPv6 in packet:
                # Handle IPv6 packets
                ipv6_layer = packet[IPv6]
                src_ip = ipv6_layer.src
                dst_ip = ipv6_layer.dst
                protocol = "IPv6"
                src_port = dst_port = 0
                payload = b""
                
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = "TCPv6"
                    payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = "UDPv6"
                    payload = bytes(udp_layer.payload) if udp_layer.payload else b""
                
                self._update_flow(src_ip, dst_ip, src_port, dst_port, 
                                protocol, len(packet), payload)
                self.byte_count += len(packet)
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _update_flow(self, src_ip: str, dst_ip: str, src_port: int, 
                    dst_port: int, protocol: str, packet_size: int, payload: bytes):
        """Update flow statistics"""
        flow_key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        
        with self._flow_lock:
            if flow_key not in self.flows:
                # Classify application
                app = ApplicationClassifier.classify_flow(src_port, dst_port, payload)
                
                # Determine priority based on application
                priority = self._get_priority_for_app(app)
                
                self.flows[flow_key] = TrafficFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    application=app,
                    priority=priority,
                    first_seen=datetime.now()
                )
            
            flow = self.flows[flow_key]
            flow.last_seen = datetime.now()
            
            # Update statistics based on direction
            if (flow.src_ip, flow.src_port) == (src_ip, src_port):
                flow.bytes_sent += packet_size
                flow.packets_sent += 1
            else:
                flow.bytes_received += packet_size
                flow.packets_received += 1
    
    def _get_priority_for_app(self, app: str) -> str:
        """Determine QoS priority for application"""
        high_priority = ["VoIP", "Video", "Gaming", "RDP", "SSH"]
        medium_priority = ["HTTP", "HTTPS", "DNS", "SMTP", "IMAP", "POP3"]
        low_priority = ["FTP", "BitTorrent", "Backup", "Update"]
        
        app_upper = app.upper()
        if any(hp in app_upper for hp in high_priority):
            return "high"
        elif any(mp in app_upper for mp in medium_priority):
            return "medium"
        elif any(lp in app_upper for lp in low_priority):
            return "low"
        return "normal"
    
    def start_capture(self) -> bool:
        """Start traffic capture"""
        if self.is_running:
            logger.warning("Traffic capture is already running")
            return False
        
        try:
            self.is_running = True
            self._stop_event.clear()
            self.start_time = datetime.now()
            self.packet_count = 0
            self.byte_count = 0
            
            # Start capture thread
            self._capture_thread = Thread(target=self._capture_loop, daemon=True)
            self._capture_thread.start()
            
            logger.info(f"Started traffic capture on interface: {self.interface or 'default'}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start traffic capture: {e}")
            self.is_running = False
            return False
    
    def _capture_loop(self):
        """Main capture loop"""
        try:
            scapy.sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self._packet_handler,
                stop_filter=lambda x: self._stop_event.is_set(),
                store=0  # Don't store packets in memory
            )
        except Exception as e:
            logger.error(f"Capture loop error: {e}")
        finally:
            self.is_running = False
    
    def stop_capture(self):
        """Stop traffic capture"""
        if not self.is_running:
            logger.warning("Traffic capture is not running")
            return
        
        self._stop_event.set()
        self.is_running = False
        
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5)
        
        logger.info("Traffic capture stopped")
    
    def get_current_stats(self) -> TrafficStats:
        """Get current traffic statistics"""
        with self._flow_lock:
            flows = list(self.flows.values())
        
        now = datetime.now()
        total_bytes = sum(f.bytes_sent + f.bytes_received for f in flows)
        total_packets = sum(f.packets_sent + f.packets_received for f in flows)
        
        # Protocol distribution
        protocol_dist = defaultdict(int)
        tcp_packets = udp_packets = icmp_packets = 0
        http_traffic = https_traffic = ssh_traffic = 0
        ftp_traffic = dns_traffic = 0
        
        for flow in flows:
            proto_packets = flow.packets_sent + flow.packets_received
            protocol_dist[flow.protocol] += proto_packets
            
            if flow.protocol.upper().startswith("TCP"):
                tcp_packets += proto_packets
            elif flow.protocol.upper().startswith("UDP"):
                udp_packets += proto_packets
            elif flow.protocol.upper() == "ICMP":
                icmp_packets += proto_packets
            
            # Application-specific traffic
            app = flow.application.upper()
            traffic_bytes = flow.bytes_sent + flow.bytes_received
            
            if app == "HTTP":
                http_traffic += traffic_bytes
            elif app == "HTTPS":
                https_traffic += traffic_bytes
            elif app == "SSH":
                ssh_traffic += traffic_bytes
            elif app == "FTP":
                ftp_traffic += traffic_bytes
            elif app == "DNS":
                dns_traffic += traffic_bytes
        
        # Top talkers (by bytes)
        top_talkers = []
        flow_stats = []
        
        for flow in flows:
            total_flow_bytes = flow.bytes_sent + flow.bytes_received
            if total_flow_bytes > 0:
                flow_stats.append({
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "application": flow.application,
                    "bytes": total_flow_bytes,
                    "packets": flow.packets_sent + flow.packets_received
                })
        
        # Sort by bytes and get top 10
        flow_stats.sort(key=lambda x: x["bytes"], reverse=True)
        top_talkers = flow_stats[:10]
        
        # Calculate bandwidth utilization (mock value for now)
        # In real implementation, this would be based on interface capacity
        bandwidth_utilization = min(100.0, (total_bytes / (1024 * 1024)) * 10)  # Rough estimation
        
        stats = TrafficStats(
            timestamp=now,
            total_bytes=total_bytes,
            total_packets=total_packets,
            tcp_packets=tcp_packets,
            udp_packets=udp_packets,
            icmp_packets=icmp_packets,
            http_traffic=http_traffic,
            https_traffic=https_traffic,
            ssh_traffic=ssh_traffic,
            ftp_traffic=ftp_traffic,
            dns_traffic=dns_traffic,
            top_talkers=top_talkers,
            protocol_distribution=dict(protocol_dist),
            bandwidth_utilization=bandwidth_utilization
        )
        
        # Add to history
        with self._stats_lock:
            self.stats_history.append(stats)
        
        return stats
    
    def get_flow_by_criteria(self, **criteria) -> List[TrafficFlow]:
        """Get flows matching specific criteria"""
        with self._flow_lock:
            flows = list(self.flows.values())
        
        filtered_flows = []
        for flow in flows:
            match = True
            for key, value in criteria.items():
                if hasattr(flow, key):
                    if getattr(flow, key) != value:
                        match = False
                        break
            if match:
                filtered_flows.append(flow)
        
        return filtered_flows
    
    def get_top_applications(self, limit: int = 10) -> List[Dict]:
        """Get top applications by traffic volume"""
        app_stats = defaultdict(lambda: {"bytes": 0, "packets": 0, "flows": 0})
        
        with self._flow_lock:
            for flow in self.flows.values():
                app = flow.application
                app_stats[app]["bytes"] += flow.bytes_sent + flow.bytes_received
                app_stats[app]["packets"] += flow.packets_sent + flow.packets_received
                app_stats[app]["flows"] += 1
        
        # Convert to list and sort by bytes
        apps = [{"application": app, **stats} for app, stats in app_stats.items()]
        apps.sort(key=lambda x: x["bytes"], reverse=True)
        
        return apps[:limit]
    
    def get_bandwidth_trends(self, duration_minutes: int = 60) -> Dict:
        """Get bandwidth usage trends over time"""
        cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
        
        with self._stats_lock:
            recent_stats = [s for s in self.stats_history if s.timestamp >= cutoff_time]
        
        if not recent_stats:
            return {"timestamps": [], "bandwidth": [], "packets": []}
        
        timestamps = [s.timestamp.isoformat() for s in recent_stats]
        bandwidth = [s.total_bytes for s in recent_stats]
        packets = [s.total_packets for s in recent_stats]
        
        return {
            "timestamps": timestamps,
            "bandwidth": bandwidth,
            "packets": packets,
            "average_bandwidth": statistics.mean(bandwidth) if bandwidth else 0,
            "peak_bandwidth": max(bandwidth) if bandwidth else 0,
            "total_packets": sum(packets) if packets else 0
        }
    
    def get_protocol_analysis(self) -> Dict:
        """Analyze protocol distribution and characteristics"""
        protocol_stats = defaultdict(lambda: {
            "bytes": 0,
            "packets": 0,
            "flows": 0,
            "avg_packet_size": 0,
            "applications": set()
        })
        
        with self._flow_lock:
            for flow in self.flows.values():
                protocol = flow.protocol
                total_bytes = flow.bytes_sent + flow.bytes_received
                total_packets = flow.packets_sent + flow.packets_received
                
                protocol_stats[protocol]["bytes"] += total_bytes
                protocol_stats[protocol]["packets"] += total_packets
                protocol_stats[protocol]["flows"] += 1
                protocol_stats[protocol]["applications"].add(flow.application)
        
        # Calculate averages and convert sets to lists
        for protocol, stats in protocol_stats.items():
            if stats["packets"] > 0:
                stats["avg_packet_size"] = stats["bytes"] / stats["packets"]
            stats["applications"] = list(stats["applications"])
        
        return dict(protocol_stats)
    
    def export_flows(self, filepath: str, format: str = "json") -> bool:
        """Export flow data to file"""
        try:
            with self._flow_lock:
                flows_data = [asdict(flow) for flow in self.flows.values()]
            
            # Convert datetime objects to strings
            for flow_data in flows_data:
                if flow_data["first_seen"]:
                    flow_data["first_seen"] = flow_data["first_seen"].isoformat()
                if flow_data["last_seen"]:
                    flow_data["last_seen"] = flow_data["last_seen"].isoformat()
            
            if format.lower() == "json":
                with open(filepath, 'w') as f:
                    json.dump(flows_data, f, indent=2)
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            logger.info(f"Exported {len(flows_data)} flows to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export flows: {e}")
            return False
    
    def cleanup_old_flows(self, age_hours: int = 24):
        """Remove flows older than specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=age_hours)
        
        with self._flow_lock:
            old_flows = [k for k, flow in self.flows.items() 
                        if flow.last_seen < cutoff_time]
            
            for flow_key in old_flows:
                del self.flows[flow_key]
        
        logger.info(f"Cleaned up {len(old_flows)} old flows")
    
    def get_performance_metrics(self) -> Dict:
        """Get analyzer performance metrics"""
        uptime = datetime.now() - self.start_time if self.start_time else timedelta(0)
        
        return {
            "uptime_seconds": uptime.total_seconds(),
            "packets_processed": self.packet_count,
            "bytes_processed": self.byte_count,
            "active_flows": len(self.flows),
            "packets_per_second": self.packet_count / uptime.total_seconds() if uptime.total_seconds() > 0 else 0,
            "bytes_per_second": self.byte_count / uptime.total_seconds() if uptime.total_seconds() > 0 else 0,
            "memory_usage_mb": psutil.Process().memory_info().rss / 1024 / 1024
        }

if __name__ == "__main__":
    # Example usage
    analyzer = TrafficAnalyzer()
    
    print("Starting traffic analysis...")
    if analyzer.start_capture():
        try:
            time.sleep(30)  # Capture for 30 seconds
            
            stats = analyzer.get_current_stats()
            print(f"\nTraffic Statistics:")
            print(f"Total Bytes: {stats.total_bytes:,}")
            print(f"Total Packets: {stats.total_packets:,}")
            print(f"TCP Packets: {stats.tcp_packets:,}")
            print(f"UDP Packets: {stats.udp_packets:,}")
            
            print(f"\nTop Applications:")
            for app in analyzer.get_top_applications(5):
                print(f"  {app['application']}: {app['bytes']:,} bytes")
            
            # Export data
            analyzer.export_flows("traffic_flows.json")
            
        except KeyboardInterrupt:
            print("\nStopping capture...")
        finally:
            analyzer.stop_capture()
    else:
        print("Failed to start traffic capture")