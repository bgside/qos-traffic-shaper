"""
Network Monitor Module
Real-time network monitoring and health checking
"""
import time
import json
import logging
import subprocess
import psutil
import socket
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from threading import Thread, Lock, Event
from collections import deque, defaultdict
import statistics

logger = logging.getLogger(__name__)

@dataclass
class NetworkHealth:
    """Network health status"""
    interface: str
    status: str  # up, down, degraded
    latency_ms: float
    packet_loss_percent: float
    bandwidth_utilization_percent: float
    errors: int
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class LatencyTest:
    """Latency test result"""
    target: str
    latency_ms: float
    packet_loss: float
    status: str
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class BandwidthTest:
    """Bandwidth test result"""
    interface: str
    download_mbps: float
    upload_mbps: float
    test_duration: float
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class NetworkMonitor:
    """Real-time network monitoring and health checking"""
    
    def __init__(self):
        self.health_status: Dict[str, NetworkHealth] = {}
        self.latency_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.bandwidth_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.alerts: List[Dict] = []
        self._lock = Lock()
        self._monitoring_active = False
        self._monitor_thread = None
        self._stop_event = Event()
        
        # Monitoring configuration
        self.monitor_interval = 10  # seconds
        self.ping_targets = [
            "8.8.8.8",      # Google DNS
            "1.1.1.1",      # Cloudflare DNS
            "208.67.222.222" # OpenDNS
        ]
        self.latency_thresholds = {
            'good': 50,      # ms
            'degraded': 150,  # ms
            'poor': 500      # ms
        }
        
        # Interface monitoring
        self.interface_stats = {}
        self.prev_interface_stats = {}
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self._monitoring_active:
            logger.warning("Network monitoring is already active")
            return
        
        self._monitoring_active = True
        self._stop_event.clear()
        self._monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        logger.info("Started network monitoring")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        if not self._monitoring_active:
            return
        
        self._stop_event.set()
        self._monitoring_active = False
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        
        logger.info("Stopped network monitoring")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while not self._stop_event.is_set():
            try:
                # Monitor interfaces
                self._monitor_interfaces()
                
                # Test connectivity
                self._test_connectivity()
                
                # Check network health
                self._update_network_health()
                
                # Check for alerts
                self._check_alerts()
                
                # Sleep for monitoring interval
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitor_interval)
    
    def _monitor_interfaces(self):
        """Monitor network interfaces"""
        try:
            # Get current interface statistics
            current_stats = psutil.net_io_counters(pernic=True)
            current_time = datetime.now()
            
            with self._lock:
                for interface, stats in current_stats.items():
                    # Skip loopback and virtual interfaces
                    if interface.startswith(('lo', 'docker', 'veth', 'br-')):
                        continue
                    
                    prev_stats = self.prev_interface_stats.get(interface)
                    
                    if prev_stats:
                        time_delta = (current_time - prev_stats['timestamp']).total_seconds()
                        
                        if time_delta > 0:
                            # Calculate throughput
                            bytes_sent_delta = stats.bytes_sent - prev_stats['stats'].bytes_sent
                            bytes_recv_delta = stats.bytes_recv - prev_stats['stats'].bytes_recv
                            
                            sent_bps = bytes_sent_delta / time_delta
                            recv_bps = bytes_recv_delta / time_delta
                            
                            # Calculate errors
                            errors = stats.errin + stats.errout + stats.dropin + stats.dropout
                            prev_errors = (prev_stats['stats'].errin + prev_stats['stats'].errout + 
                                         prev_stats['stats'].dropin + prev_stats['stats'].dropout)
                            error_delta = errors - prev_errors
                            
                            # Store interface statistics
                            interface_data = {
                                'interface': interface,
                                'bytes_sent_per_sec': sent_bps,
                                'bytes_recv_per_sec': recv_bps,
                                'total_bps': sent_bps + recv_bps,
                                'packets_sent': stats.packets_sent,
                                'packets_recv': stats.packets_recv,
                                'errors': errors,
                                'error_delta': error_delta,
                                'timestamp': current_time
                            }
                            
                            self.interface_stats[interface] = interface_data
                    
                    # Store current stats for next iteration
                    self.prev_interface_stats[interface] = {
                        'stats': stats,
                        'timestamp': current_time
                    }
        
        except Exception as e:
            logger.error(f"Error monitoring interfaces: {e}")
    
    def _test_connectivity(self):
        """Test network connectivity to targets"""
        for target in self.ping_targets:
            try:
                latency_result = self._ping_test(target)
                
                with self._lock:
                    self.latency_history[target].append(latency_result)
                
            except Exception as e:
                logger.error(f"Error testing connectivity to {target}: {e}")
    
    def _ping_test(self, target: str, count: int = 3) -> LatencyTest:
        """Perform ping test to target"""
        try:
            # Use system ping command
            import platform
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["ping", "-n", str(count), target]
            else:
                cmd = ["ping", "-c", str(count), target]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse ping output
                output = result.stdout
                latency, packet_loss = self._parse_ping_output(output, system)
                
                status = "good"
                if latency > self.latency_thresholds['poor']:
                    status = "poor"
                elif latency > self.latency_thresholds['degraded']:
                    status = "degraded"
                
                return LatencyTest(
                    target=target,
                    latency_ms=latency,
                    packet_loss=packet_loss,
                    status=status
                )
            else:
                return LatencyTest(
                    target=target,
                    latency_ms=999999,
                    packet_loss=100.0,
                    status="failed"
                )
        
        except Exception as e:
            logger.error(f"Ping test failed for {target}: {e}")
            return LatencyTest(
                target=target,
                latency_ms=999999,
                packet_loss=100.0,
                status="error"
            )
    
    def _parse_ping_output(self, output: str, system: str) -> Tuple[float, float]:
        """Parse ping command output"""
        try:
            lines = output.split('\n')
            latencies = []
            packet_loss = 0.0
            
            if system == "windows":
                for line in lines:
                    if "time=" in line or "time<" in line:
                        # Extract latency
                        if "time=" in line:
                            time_part = line.split("time=")[1].split("ms")[0]
                            latencies.append(float(time_part))
                        elif "time<" in line:
                            time_part = line.split("time<")[1].split("ms")[0]
                            latencies.append(float(time_part))
                    
                    elif "loss" in line and "%" in line:
                        # Extract packet loss
                        loss_part = line.split("(")[1].split("%")[0]
                        packet_loss = float(loss_part)
            
            else:  # Linux/Unix
                for line in lines:
                    if "time=" in line:
                        time_part = line.split("time=")[1].split()[0]
                        latencies.append(float(time_part))
                    elif "packet loss" in line:
                        loss_part = line.split(",")[2].strip().split("%")[0]
                        packet_loss = float(loss_part)
            
            avg_latency = statistics.mean(latencies) if latencies else 999999
            return avg_latency, packet_loss
        
        except Exception as e:
            logger.error(f"Error parsing ping output: {e}")
            return 999999, 100.0
    
    def _update_network_health(self):
        """Update overall network health status"""
        try:
            with self._lock:
                for interface, stats in self.interface_stats.items():
                    # Calculate bandwidth utilization (estimate)
                    interface_speed = self._get_interface_speed(interface)
                    utilization = (stats['total_bps'] * 8) / (interface_speed * 1_000_000) * 100
                    utilization = min(100.0, utilization)
                    
                    # Determine overall status
                    status = "up"
                    
                    # Check for high error rates
                    if stats['error_delta'] > 10:
                        status = "degraded"
                    
                    # Check bandwidth utilization
                    if utilization > 90:
                        status = "degraded"
                    
                    # Get average latency for this interface (use first ping target as proxy)
                    avg_latency = 0
                    packet_loss = 0
                    
                    if self.ping_targets and self.ping_targets[0] in self.latency_history:
                        recent_tests = list(self.latency_history[self.ping_targets[0]])[-5:]
                        if recent_tests:
                            avg_latency = statistics.mean([t.latency_ms for t in recent_tests])
                            packet_loss = statistics.mean([t.packet_loss for t in recent_tests])
                    
                    if avg_latency > self.latency_thresholds['degraded'] or packet_loss > 5:
                        status = "degraded"
                    
                    if avg_latency > self.latency_thresholds['poor'] or packet_loss > 20:
                        status = "down"
                    
                    # Update health status
                    self.health_status[interface] = NetworkHealth(
                        interface=interface,
                        status=status,
                        latency_ms=avg_latency,
                        packet_loss_percent=packet_loss,
                        bandwidth_utilization_percent=utilization,
                        errors=stats['errors']
                    )
        
        except Exception as e:
            logger.error(f"Error updating network health: {e}")
    
    def _get_interface_speed(self, interface: str) -> float:
        """Get interface speed in Mbps"""
        try:
            import platform
            if platform.system() == "Linux":
                speed_file = f"/sys/class/net/{interface}/speed"
                try:
                    with open(speed_file, 'r') as f:
                        return float(f.read().strip())
                except FileNotFoundError:
                    pass
            
            # Fallback estimates based on interface name
            if 'eth' in interface.lower():
                return 1000.0  # 1 Gbps
            elif 'wlan' in interface.lower() or 'wifi' in interface.lower():
                return 300.0   # 300 Mbps
            else:
                return 100.0   # 100 Mbps default
        
        except Exception:
            return 100.0
    
    def _check_alerts(self):
        """Check for network alerts"""
        try:
            current_time = datetime.now()
            
            with self._lock:
                for interface, health in self.health_status.items():
                    # Check for degraded/down interfaces
                    if health.status in ["degraded", "down"]:
                        alert = {
                            'type': 'interface_status',
                            'severity': 'warning' if health.status == 'degraded' else 'critical',
                            'interface': interface,
                            'status': health.status,
                            'message': f"Interface {interface} is {health.status}",
                            'details': {
                                'latency_ms': health.latency_ms,
                                'packet_loss_percent': health.packet_loss_percent,
                                'bandwidth_utilization_percent': health.bandwidth_utilization_percent,
                                'errors': health.errors
                            },
                            'timestamp': current_time.isoformat()
                        }
                        self._add_alert(alert)
                    
                    # Check for high bandwidth utilization
                    if health.bandwidth_utilization_percent > 80:
                        alert = {
                            'type': 'bandwidth_utilization',
                            'severity': 'warning',
                            'interface': interface,
                            'message': f"High bandwidth utilization on {interface}: {health.bandwidth_utilization_percent:.1f}%",
                            'details': {
                                'utilization_percent': health.bandwidth_utilization_percent
                            },
                            'timestamp': current_time.isoformat()
                        }
                        self._add_alert(alert)
                    
                    # Check for high error rates
                    interface_stats = self.interface_stats.get(interface, {})
                    if interface_stats.get('error_delta', 0) > 50:
                        alert = {
                            'type': 'network_errors',
                            'severity': 'warning',
                            'interface': interface,
                            'message': f"High error rate detected on {interface}",
                            'details': {
                                'error_delta': interface_stats['error_delta'],
                                'total_errors': health.errors
                            },
                            'timestamp': current_time.isoformat()
                        }
                        self._add_alert(alert)
                
                # Check connectivity alerts
                for target, history in self.latency_history.items():
                    if history:
                        recent_test = history[-1]
                        if recent_test.status in ["poor", "failed"]:
                            alert = {
                                'type': 'connectivity',
                                'severity': 'critical' if recent_test.status == 'failed' else 'warning',
                                'target': target,
                                'message': f"Connectivity to {target} is {recent_test.status}",
                                'details': {
                                    'latency_ms': recent_test.latency_ms,
                                    'packet_loss': recent_test.packet_loss,
                                    'status': recent_test.status
                                },
                                'timestamp': current_time.isoformat()
                            }
                            self._add_alert(alert)
        
        except Exception as e:
            logger.error(f"Error checking alerts: {e}")
    
    def _add_alert(self, alert: Dict):
        """Add alert if not duplicate"""
        # Check for duplicate alerts in last 5 minutes
        cutoff_time = datetime.now() - timedelta(minutes=5)
        
        for existing_alert in self.alerts:
            alert_time = datetime.fromisoformat(existing_alert['timestamp'])
            if (alert_time > cutoff_time and 
                existing_alert['type'] == alert['type'] and
                existing_alert.get('interface') == alert.get('interface') and
                existing_alert.get('target') == alert.get('target')):
                return  # Duplicate alert, don't add
        
        self.alerts.append(alert)
        
        # Keep only last 500 alerts
        if len(self.alerts) > 500:
            self.alerts = self.alerts[-500:]
        
        logger.warning(f"Network alert: {alert['message']}")
    
    def get_network_health(self) -> Dict:
        """Get current network health status"""
        with self._lock:
            health_data = {}
            for interface, health in self.health_status.items():
                data = asdict(health)
                if data['timestamp']:
                    data['timestamp'] = data['timestamp'].isoformat()
                health_data[interface] = data
        
        return health_data
    
    def get_interface_statistics(self, interface: str = None) -> Dict:
        """Get interface statistics"""
        with self._lock:
            if interface:
                stats = self.interface_stats.get(interface)
                if stats:
                    data = dict(stats)
                    if data['timestamp']:
                        data['timestamp'] = data['timestamp'].isoformat()
                    return data
                return {}
            else:
                all_stats = {}
                for iface, stats in self.interface_stats.items():
                    data = dict(stats)
                    if data['timestamp']:
                        data['timestamp'] = data['timestamp'].isoformat()
                    all_stats[iface] = data
                return all_stats
    
    def get_latency_history(self, target: str = None, limit: int = 50) -> Dict:
        """Get latency test history"""
        with self._lock:
            if target:
                history = list(self.latency_history.get(target, []))[-limit:]
                return {
                    target: [asdict(test) for test in history]
                }
            else:
                all_history = {}
                for tgt, history in self.latency_history.items():
                    test_data = []
                    for test in list(history)[-limit:]:
                        data = asdict(test)
                        if data['timestamp']:
                            data['timestamp'] = data['timestamp'].isoformat()
                        test_data.append(data)
                    all_history[tgt] = test_data
                return all_history
    
    def get_alerts(self, limit: int = 100, severity: str = None) -> List[Dict]:
        """Get recent network alerts"""
        alerts = self.alerts[-limit:]
        
        if severity:
            alerts = [alert for alert in alerts if alert['severity'] == severity]
        
        return alerts
    
    def clear_alerts(self, older_than_hours: int = 24):
        """Clear old alerts"""
        cutoff_time = datetime.now() - timedelta(hours=older_than_hours)
        
        self.alerts = [
            alert for alert in self.alerts
            if datetime.fromisoformat(alert['timestamp']) > cutoff_time
        ]
        
        logger.info(f"Cleared alerts older than {older_than_hours} hours")
    
    def test_bandwidth(self, interface: str = None) -> BandwidthTest:
        """Perform bandwidth test (simplified)"""
        try:
            start_time = time.time()
            
            # Get initial interface stats
            if interface:
                initial_stats = psutil.net_io_counters(pernic=True).get(interface)
            else:
                initial_stats = psutil.net_io_counters()
            
            if not initial_stats:
                raise ValueError(f"Interface {interface} not found")
            
            # Wait for test duration
            test_duration = 10  # seconds
            time.sleep(test_duration)
            
            # Get final interface stats
            if interface:
                final_stats = psutil.net_io_counters(pernic=True).get(interface)
            else:
                final_stats = psutil.net_io_counters()
            
            # Calculate bandwidth
            bytes_sent_delta = final_stats.bytes_sent - initial_stats.bytes_sent
            bytes_recv_delta = final_stats.bytes_recv - initial_stats.bytes_recv
            
            upload_mbps = (bytes_sent_delta * 8) / (test_duration * 1_000_000)
            download_mbps = (bytes_recv_delta * 8) / (test_duration * 1_000_000)
            
            return BandwidthTest(
                interface=interface or "all",
                download_mbps=download_mbps,
                upload_mbps=upload_mbps,
                test_duration=test_duration
            )
        
        except Exception as e:
            logger.error(f"Bandwidth test failed: {e}")
            return BandwidthTest(
                interface=interface or "all",
                download_mbps=0.0,
                upload_mbps=0.0,
                test_duration=0.0
            )
    
    def get_network_topology(self) -> Dict:
        """Get basic network topology information"""
        topology = {
            'interfaces': [],
            'routes': [],
            'dns_servers': [],
            'default_gateway': None
        }
        
        try:
            # Get network interfaces
            interfaces = psutil.net_if_addrs()
            for interface, addresses in interfaces.items():
                interface_info = {
                    'name': interface,
                    'addresses': []
                }
                
                for addr in addresses:
                    addr_info = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    interface_info['addresses'].append(addr_info)
                
                topology['interfaces'].append(interface_info)
            
            # Get default gateway (simplified)
            try:
                gateways = psutil.net_if_stats()
                # This is a simplified approach - real implementation would need more detailed route parsing
                topology['default_gateway'] = "Not implemented"
            except Exception:
                pass
        
        except Exception as e:
            logger.error(f"Error getting network topology: {e}")
        
        return topology
    
    def diagnose_network_issues(self) -> Dict:
        """Diagnose potential network issues"""
        issues = []
        recommendations = []
        
        try:
            with self._lock:
                # Check interface health
                for interface, health in self.health_status.items():
                    if health.status == "down":
                        issues.append(f"Interface {interface} is down")
                        recommendations.append(f"Check physical connection and driver for {interface}")
                    
                    elif health.status == "degraded":
                        if health.packet_loss_percent > 10:
                            issues.append(f"High packet loss on {interface}: {health.packet_loss_percent:.1f}%")
                            recommendations.append(f"Check network cables and switch ports for {interface}")
                        
                        if health.latency_ms > self.latency_thresholds['degraded']:
                            issues.append(f"High latency on {interface}: {health.latency_ms:.1f}ms")
                            recommendations.append(f"Check network congestion and routing for {interface}")
                        
                        if health.bandwidth_utilization_percent > 80:
                            issues.append(f"High bandwidth utilization on {interface}: {health.bandwidth_utilization_percent:.1f}%")
                            recommendations.append(f"Consider upgrading bandwidth or implementing QoS on {interface}")
                
                # Check connectivity
                failed_targets = []
                for target, history in self.latency_history.items():
                    if history and history[-1].status == "failed":
                        failed_targets.append(target)
                
                if failed_targets:
                    issues.append(f"Cannot reach external targets: {', '.join(failed_targets)}")
                    recommendations.append("Check internet connectivity and DNS resolution")
                
                # Check for error patterns
                high_error_interfaces = []
                for interface, stats in self.interface_stats.items():
                    if stats.get('error_delta', 0) > 20:
                        high_error_interfaces.append(interface)
                
                if high_error_interfaces:
                    issues.append(f"High error rates on interfaces: {', '.join(high_error_interfaces)}")
                    recommendations.append("Check for hardware issues, driver problems, or network congestion")
        
        except Exception as e:
            logger.error(f"Error diagnosing network issues: {e}")
            issues.append(f"Diagnostic error: {e}")
        
        return {
            'issues_found': len(issues),
            'issues': issues,
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat()
        }

if __name__ == "__main__":
    # Example usage
    monitor = NetworkMonitor()
    
    print("Starting network monitoring...")
    monitor.start_monitoring()
    
    try:
        # Let it run for a bit
        time.sleep(30)
        
        # Get health status
        health = monitor.get_network_health()
        print(f"\nNetwork Health:")
        for interface, status in health.items():
            print(f"  {interface}: {status['status']} (Latency: {status['latency_ms']:.1f}ms, Loss: {status['packet_loss_percent']:.1f}%)")
        
        # Get alerts
        alerts = monitor.get_alerts(limit=10)
        print(f"\nRecent Alerts: {len(alerts)}")
        for alert in alerts[-3:]:
            print(f"  {alert['severity'].upper()}: {alert['message']}")
        
        # Diagnose issues
        diagnosis = monitor.diagnose_network_issues()
        print(f"\nNetwork Diagnosis:")
        print(f"  Issues Found: {diagnosis['issues_found']}")
        for issue in diagnosis['issues'][:3]:
            print(f"  - {issue}")
    
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
    finally:
        monitor.stop_monitoring()