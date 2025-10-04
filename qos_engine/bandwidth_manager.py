"""
Bandwidth Manager Module
Dynamic bandwidth allocation and traffic shaping
"""
import os
import json
import logging
import subprocess
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from threading import Thread, Lock, Event
import psutil
import platform
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class BandwidthAllocation:
    """Bandwidth allocation configuration"""
    interface: str
    total_bandwidth_mbps: float
    allocated_mbps: float
    reserved_mbps: float
    application: str
    priority: str
    min_guaranteed_mbps: float = 0.0
    max_burst_mbps: float = 0.0
    current_usage_mbps: float = 0.0
    queue_name: str = ""
    created_at: datetime = None
    last_updated: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.last_updated is None:
            self.last_updated = datetime.now()

@dataclass
class InterfaceStats:
    """Network interface statistics"""
    interface: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errin: int
    errout: int
    dropin: int
    dropout: int
    speed_mbps: float
    utilization_percent: float
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class TrafficShaper:
    """Traffic shaping implementation using system tools"""
    
    def __init__(self):
        self.system = platform.system()
        self.is_linux = self.system == "Linux"
        self.is_windows = self.system == "Windows"
        self.is_mac = self.system == "Darwin"
        
    def _run_command(self, cmd: List[str]) -> Tuple[bool, str]:
        """Execute system command safely"""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, str(e)
    
    def create_qdisc(self, interface: str, bandwidth_mbps: float) -> bool:
        """Create traffic control queueing discipline (Linux)"""
        if not self.is_linux:
            logger.warning("Traffic shaping only supported on Linux")
            return False
        
        try:
            # Remove existing qdisc
            self._run_command(["tc", "qdisc", "del", "dev", interface, "root"])
            
            # Create HTB root qdisc
            bandwidth_kbps = int(bandwidth_mbps * 1000)
            success, output = self._run_command([
                "tc", "qdisc", "add", "dev", interface, "root", "handle", "1:",
                "htb", "default", "30"
            ])
            
            if success:
                # Create root class
                success, output = self._run_command([
                    "tc", "class", "add", "dev", interface, "parent", "1:",
                    "classid", "1:1", "htb", "rate", f"{bandwidth_kbps}kbit"
                ])
            
            if success:
                logger.info(f"Created traffic control on {interface} with {bandwidth_mbps}Mbps")
            else:
                logger.error(f"Failed to create qdisc: {output}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error creating qdisc: {e}")
            return False
    
    def add_class(self, interface: str, class_id: str, parent_id: str,
                  rate_mbps: float, ceil_mbps: float = None, priority: int = 1) -> bool:
        """Add traffic class (Linux)"""
        if not self.is_linux:
            return False
        
        try:
            rate_kbps = int(rate_mbps * 1000)
            ceil_kbps = int((ceil_mbps or rate_mbps) * 1000)
            
            success, output = self._run_command([
                "tc", "class", "add", "dev", interface,
                "parent", parent_id, "classid", class_id,
                "htb", "rate", f"{rate_kbps}kbit",
                "ceil", f"{ceil_kbps}kbit",
                "prio", str(priority)
            ])
            
            if success:
                logger.info(f"Added class {class_id} with {rate_mbps}Mbps rate")
            else:
                logger.error(f"Failed to add class: {output}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error adding class: {e}")
            return False
    
    def add_filter(self, interface: str, class_id: str, src_ip: str = None,
                   dst_ip: str = None, src_port: int = None, dst_port: int = None,
                   protocol: str = None) -> bool:
        """Add traffic filter (Linux)"""
        if not self.is_linux:
            return False
        
        try:
            cmd = ["tc", "filter", "add", "dev", interface, "protocol", "ip",
                   "parent", "1:", "prio", "1", "u32"]
            
            # Build filter match criteria
            if src_ip:
                cmd.extend(["match", "ip", "src", src_ip])
            if dst_ip:
                cmd.extend(["match", "ip", "dst", dst_ip])
            if protocol:
                if protocol.lower() == "tcp":
                    cmd.extend(["match", "ip", "protocol", "6", "0xff"])
                elif protocol.lower() == "udp":
                    cmd.extend(["match", "ip", "protocol", "17", "0xff"])
            
            if src_port:
                cmd.extend(["match", "ip", "sport", str(src_port), "0xffff"])
            if dst_port:
                cmd.extend(["match", "ip", "dport", str(dst_port), "0xffff"])
            
            cmd.extend(["flowid", class_id])
            
            success, output = self._run_command(cmd)
            
            if success:
                logger.info(f"Added filter for class {class_id}")
            else:
                logger.error(f"Failed to add filter: {output}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error adding filter: {e}")
            return False
    
    def remove_shaping(self, interface: str) -> bool:
        """Remove all traffic shaping from interface"""
        if not self.is_linux:
            return False
        
        try:
            success, output = self._run_command([
                "tc", "qdisc", "del", "dev", interface, "root"
            ])
            
            if success:
                logger.info(f"Removed traffic shaping from {interface}")
            else:
                logger.warning(f"No shaping to remove on {interface}: {output}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error removing shaping: {e}")
            return False
    
    def get_tc_stats(self, interface: str) -> Dict:
        """Get traffic control statistics (Linux)"""
        if not self.is_linux:
            return {}
        
        try:
            success, output = self._run_command([
                "tc", "-s", "class", "show", "dev", interface
            ])
            
            if success:
                return self._parse_tc_stats(output)
            else:
                logger.error(f"Failed to get TC stats: {output}")
                return {}
            
        except Exception as e:
            logger.error(f"Error getting TC stats: {e}")
            return {}
    
    def _parse_tc_stats(self, output: str) -> Dict:
        """Parse tc statistics output"""
        stats = {}
        current_class = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('class htb'):
                # Extract class ID
                parts = line.split()
                if len(parts) >= 3:
                    current_class = parts[2]
                    stats[current_class] = {}
            
            elif 'Sent' in line and current_class:
                # Parse sent statistics
                # Format: " Sent 1234 bytes 5 pkt (dropped 0, overlimits 0 requeues 0)"
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        bytes_sent = int(parts[1])
                        packets_sent = int(parts[3])
                        stats[current_class]['bytes_sent'] = bytes_sent
                        stats[current_class]['packets_sent'] = packets_sent
                        
                        # Extract dropped, overlimits, requeues
                        if 'dropped' in line:
                            dropped_idx = parts.index('dropped') + 1
                            stats[current_class]['dropped'] = int(parts[dropped_idx].rstrip(','))
                        if 'overlimits' in line:
                            overlimits_idx = parts.index('overlimits') + 1
                            stats[current_class]['overlimits'] = int(parts[overlimits_idx])
                    except (ValueError, IndexError):
                        pass
            
            elif 'rate' in line and current_class:
                # Parse rate information
                # Format: " rate 123Kbit 456pps backlog 0b 0p requeues 0"
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.endswith('bit'):
                        try:
                            rate_str = part[:-3]  # Remove 'bit'
                            if rate_str.endswith('K'):
                                rate = float(rate_str[:-1]) * 1000
                            elif rate_str.endswith('M'):
                                rate = float(rate_str[:-1]) * 1000000
                            else:
                                rate = float(rate_str)
                            stats[current_class]['rate_bps'] = rate
                        except ValueError:
                            pass
        
        return stats

class BandwidthManager:
    """Dynamic bandwidth allocation and management"""
    
    def __init__(self):
        self.allocations: Dict[str, BandwidthAllocation] = {}
        self.interface_stats: Dict[str, InterfaceStats] = {}
        self.traffic_shaper = TrafficShaper()
        self._lock = Lock()
        self._monitoring_active = False
        self._monitor_thread = None
        self._stop_event = Event()
        
        # Load existing allocations
        self._load_allocations()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def _load_allocations(self):
        """Load bandwidth allocations from file"""
        try:
            if os.path.exists('bandwidth_allocations.json'):
                with open('bandwidth_allocations.json', 'r') as f:
                    data = json.load(f)
                
                for alloc_data in data:
                    # Convert datetime strings back to datetime objects
                    if alloc_data.get('created_at'):
                        alloc_data['created_at'] = datetime.fromisoformat(alloc_data['created_at'])
                    if alloc_data.get('last_updated'):
                        alloc_data['last_updated'] = datetime.fromisoformat(alloc_data['last_updated'])
                    
                    allocation = BandwidthAllocation(**alloc_data)
                    key = f"{allocation.interface}_{allocation.application}_{allocation.priority}"
                    self.allocations[key] = allocation
                
                logger.info(f"Loaded {len(self.allocations)} bandwidth allocations")
        
        except Exception as e:
            logger.error(f"Failed to load allocations: {e}")
    
    def _save_allocations(self):
        """Save bandwidth allocations to file"""
        try:
            allocations_data = []
            for allocation in self.allocations.values():
                data = asdict(allocation)
                # Convert datetime objects to strings
                if data['created_at']:
                    data['created_at'] = data['created_at'].isoformat()
                if data['last_updated']:
                    data['last_updated'] = data['last_updated'].isoformat()
                allocations_data.append(data)
            
            with open('bandwidth_allocations.json', 'w') as f:
                json.dump(allocations_data, f, indent=2)
            
            logger.debug(f"Saved {len(allocations_data)} bandwidth allocations")
        
        except Exception as e:
            logger.error(f"Failed to save allocations: {e}")
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        interfaces = []
        try:
            stats = psutil.net_io_counters(pernic=True)
            for interface in stats.keys():
                # Filter out loopback and virtual interfaces
                if not interface.startswith(('lo', 'docker', 'veth', 'br-')):
                    interfaces.append(interface)
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
        
        return interfaces
    
    def get_interface_capacity(self, interface: str) -> float:
        """Get interface maximum capacity in Mbps"""
        try:
            # Try to get speed from system
            if platform.system() == "Linux":
                speed_file = f"/sys/class/net/{interface}/speed"
                if os.path.exists(speed_file):
                    with open(speed_file, 'r') as f:
                        speed_mbps = int(f.read().strip())
                        return speed_mbps
            
            # Fallback to common speeds based on interface name
            if 'eth' in interface.lower():
                return 1000.0  # 1 Gbps
            elif 'wlan' in interface.lower() or 'wifi' in interface.lower():
                return 300.0   # 300 Mbps (802.11n)
            else:
                return 100.0   # 100 Mbps default
        
        except Exception as e:
            logger.error(f"Error getting interface capacity: {e}")
            return 100.0
    
    def create_allocation(self, interface: str, application: str, 
                         allocated_mbps: float, priority: str = "normal",
                         min_guaranteed_mbps: float = 0.0,
                         max_burst_mbps: float = None) -> bool:
        """Create new bandwidth allocation"""
        try:
            if interface not in self.get_available_interfaces():
                logger.error(f"Interface {interface} not available")
                return False
            
            # Check if allocation already exists
            key = f"{interface}_{application}_{priority}"
            if key in self.allocations:
                logger.warning(f"Allocation already exists for {application} on {interface}")
                return False
            
            # Get interface capacity
            total_bandwidth = self.get_interface_capacity(interface)
            
            # Validate allocation
            if allocated_mbps > total_bandwidth:
                logger.error(f"Requested bandwidth ({allocated_mbps}Mbps) exceeds interface capacity ({total_bandwidth}Mbps)")
                return False
            
            # Check total allocations don't exceed capacity
            current_allocations = sum(
                alloc.allocated_mbps for alloc in self.allocations.values()
                if alloc.interface == interface
            )
            
            if current_allocations + allocated_mbps > total_bandwidth:
                logger.error(f"Total allocations would exceed interface capacity")
                return False
            
            # Create allocation
            with self._lock:
                allocation = BandwidthAllocation(
                    interface=interface,
                    total_bandwidth_mbps=total_bandwidth,
                    allocated_mbps=allocated_mbps,
                    reserved_mbps=min_guaranteed_mbps,
                    application=application,
                    priority=priority,
                    min_guaranteed_mbps=min_guaranteed_mbps,
                    max_burst_mbps=max_burst_mbps or allocated_mbps * 1.5,
                    queue_name=self._generate_queue_name(interface, application, priority)
                )
                
                self.allocations[key] = allocation
                self._save_allocations()
            
            # Apply traffic shaping
            self._apply_shaping(allocation)
            
            logger.info(f"Created bandwidth allocation: {allocated_mbps}Mbps for {application} on {interface}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create allocation: {e}")
            return False
    
    def _generate_queue_name(self, interface: str, application: str, priority: str) -> str:
        """Generate unique queue name"""
        # Map priority to class IDs
        priority_map = {
            "high": "1:10",
            "medium": "1:20", 
            "normal": "1:30",
            "low": "1:40"
        }
        return priority_map.get(priority, "1:30")
    
    def _apply_shaping(self, allocation: BandwidthAllocation) -> bool:
        """Apply traffic shaping for allocation"""
        try:
            interface = allocation.interface
            
            # Create root qdisc if it doesn't exist
            if not self._has_root_qdisc(interface):
                if not self.traffic_shaper.create_qdisc(interface, allocation.total_bandwidth_mbps):
                    return False
            
            # Add class for this allocation
            priority_num = {"high": 1, "medium": 2, "normal": 3, "low": 4}.get(allocation.priority, 3)
            
            success = self.traffic_shaper.add_class(
                interface=interface,
                class_id=allocation.queue_name,
                parent_id="1:1",
                rate_mbps=allocation.min_guaranteed_mbps or allocation.allocated_mbps * 0.5,
                ceil_mbps=allocation.max_burst_mbps,
                priority=priority_num
            )
            
            if success:
                logger.info(f"Applied traffic shaping for {allocation.application}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to apply shaping: {e}")
            return False
    
    def _has_root_qdisc(self, interface: str) -> bool:
        """Check if interface has root qdisc configured"""
        try:
            success, output = self.traffic_shaper._run_command([
                "tc", "qdisc", "show", "dev", interface
            ])
            
            return success and "htb" in output
        
        except Exception:
            return False
    
    def modify_allocation(self, interface: str, application: str, 
                         priority: str, new_allocated_mbps: float) -> bool:
        """Modify existing bandwidth allocation"""
        key = f"{interface}_{application}_{priority}"
        
        with self._lock:
            if key not in self.allocations:
                logger.error(f"Allocation not found: {key}")
                return False
            
            allocation = self.allocations[key]
            old_allocation = allocation.allocated_mbps
            
            # Validate new allocation
            total_bandwidth = self.get_interface_capacity(interface)
            current_allocations = sum(
                alloc.allocated_mbps for alloc in self.allocations.values()
                if alloc.interface == interface and alloc != allocation
            )
            
            if current_allocations + new_allocated_mbps > total_bandwidth:
                logger.error(f"New allocation would exceed interface capacity")
                return False
            
            # Update allocation
            allocation.allocated_mbps = new_allocated_mbps
            allocation.last_updated = datetime.now()
            
            # Update burst rate
            allocation.max_burst_mbps = new_allocated_mbps * 1.5
            
            self._save_allocations()
        
        # Re-apply shaping
        if self._apply_shaping(allocation):
            logger.info(f"Modified allocation for {application}: {old_allocation}Mbps -> {new_allocated_mbps}Mbps")
            return True
        else:
            # Rollback on failure
            with self._lock:
                allocation.allocated_mbps = old_allocation
                allocation.max_burst_mbps = old_allocation * 1.5
            return False
    
    def remove_allocation(self, interface: str, application: str, priority: str) -> bool:
        """Remove bandwidth allocation"""
        key = f"{interface}_{application}_{priority}"
        
        with self._lock:
            if key not in self.allocations:
                logger.error(f"Allocation not found: {key}")
                return False
            
            allocation = self.allocations[key]
            
            # Remove from system (simplified - would need more complex logic for real TC removal)
            # For now, we'll just remove from our tracking
            del self.allocations[key]
            self._save_allocations()
        
        logger.info(f"Removed allocation for {application} on {interface}")
        return True
    
    def get_allocations(self, interface: str = None) -> List[Dict]:
        """Get bandwidth allocations"""
        allocations = []
        
        with self._lock:
            for allocation in self.allocations.values():
                if interface is None or allocation.interface == interface:
                    data = asdict(allocation)
                    # Convert datetime to string for JSON serialization
                    if data['created_at']:
                        data['created_at'] = data['created_at'].isoformat()
                    if data['last_updated']:
                        data['last_updated'] = data['last_updated'].isoformat()
                    allocations.append(data)
        
        return allocations
    
    def start_monitoring(self):
        """Start bandwidth monitoring"""
        if self._monitoring_active:
            logger.warning("Monitoring is already active")
            return
        
        self._monitoring_active = True
        self._stop_event.clear()
        self._monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        logger.info("Started bandwidth monitoring")
    
    def stop_monitoring(self):
        """Stop bandwidth monitoring"""
        if not self._monitoring_active:
            return
        
        self._stop_event.set()
        self._monitoring_active = False
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        
        logger.info("Stopped bandwidth monitoring")
    
    def _monitor_loop(self):
        """Monitor bandwidth usage"""
        prev_stats = {}
        
        while not self._stop_event.is_set():
            try:
                # Get current interface statistics
                current_stats = psutil.net_io_counters(pernic=True)
                current_time = datetime.now()
                
                for interface, stats in current_stats.items():
                    if interface in prev_stats:
                        prev_stat = prev_stats[interface]
                        time_delta = (current_time - prev_stat['timestamp']).total_seconds()
                        
                        if time_delta > 0:
                            # Calculate throughput
                            bytes_sent_delta = stats.bytes_sent - prev_stat['stats'].bytes_sent
                            bytes_recv_delta = stats.bytes_recv - prev_stat['stats'].bytes_recv
                            
                            sent_mbps = (bytes_sent_delta * 8) / (time_delta * 1_000_000)
                            recv_mbps = (bytes_recv_delta * 8) / (time_delta * 1_000_000)
                            
                            # Update interface stats
                            capacity = self.get_interface_capacity(interface)
                            utilization = ((sent_mbps + recv_mbps) / capacity) * 100 if capacity > 0 else 0
                            
                            interface_stat = InterfaceStats(
                                interface=interface,
                                bytes_sent=stats.bytes_sent,
                                bytes_recv=stats.bytes_recv,
                                packets_sent=stats.packets_sent,
                                packets_recv=stats.packets_recv,
                                errin=stats.errin,
                                errout=stats.errout,
                                dropin=stats.dropin,
                                dropout=stats.dropout,
                                speed_mbps=capacity,
                                utilization_percent=min(100.0, utilization),
                                timestamp=current_time
                            )
                            
                            self.interface_stats[interface] = interface_stat
                    
                    # Store current stats for next iteration
                    prev_stats[interface] = {
                        'stats': stats,
                        'timestamp': current_time
                    }
                
                # Update allocation usage from TC stats
                self._update_allocation_usage()
                
                # Sleep for monitoring interval
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)
    
    def _update_allocation_usage(self):
        """Update bandwidth usage for allocations from TC stats"""
        try:
            with self._lock:
                for allocation in self.allocations.values():
                    interface = allocation.interface
                    tc_stats = self.traffic_shaper.get_tc_stats(interface)
                    
                    queue_name = allocation.queue_name
                    if queue_name in tc_stats:
                        stats = tc_stats[queue_name]
                        
                        # Calculate current usage (simplified)
                        if 'rate_bps' in stats:
                            allocation.current_usage_mbps = stats['rate_bps'] / 1_000_000
                        
                        allocation.last_updated = datetime.now()
            
        except Exception as e:
            logger.error(f"Error updating allocation usage: {e}")
    
    def get_interface_statistics(self, interface: str = None) -> List[Dict]:
        """Get interface statistics"""
        stats = []
        
        for iface, stat in self.interface_stats.items():
            if interface is None or iface == interface:
                data = asdict(stat)
                if data['timestamp']:
                    data['timestamp'] = data['timestamp'].isoformat()
                stats.append(data)
        
        return stats
    
    def get_bandwidth_summary(self) -> Dict:
        """Get overall bandwidth usage summary"""
        total_interfaces = len(self.get_available_interfaces())
        total_allocations = len(self.allocations)
        
        # Calculate total allocated bandwidth
        total_allocated = sum(alloc.allocated_mbps for alloc in self.allocations.values())
        total_capacity = sum(self.get_interface_capacity(iface) 
                           for iface in self.get_available_interfaces())
        
        # Calculate utilization
        utilization_percent = (total_allocated / total_capacity * 100) if total_capacity > 0 else 0
        
        # Get interface utilization
        interface_util = []
        for iface, stats in self.interface_stats.items():
            interface_util.append({
                "interface": iface,
                "utilization_percent": stats.utilization_percent,
                "speed_mbps": stats.speed_mbps
            })
        
        return {
            "total_interfaces": total_interfaces,
            "total_allocations": total_allocations,
            "total_allocated_mbps": total_allocated,
            "total_capacity_mbps": total_capacity,
            "allocation_utilization_percent": min(100.0, utilization_percent),
            "interface_utilization": interface_util,
            "timestamp": datetime.now().isoformat()
        }
    
    def optimize_allocations(self) -> Dict:
        """Optimize bandwidth allocations based on usage patterns"""
        try:
            recommendations = []
            
            with self._lock:
                for allocation in self.allocations.values():
                    current_usage = allocation.current_usage_mbps
                    allocated = allocation.allocated_mbps
                    
                    # Calculate usage ratio
                    usage_ratio = (current_usage / allocated) if allocated > 0 else 0
                    
                    if usage_ratio < 0.3:  # Under-utilized
                        new_allocation = max(current_usage * 1.2, allocated * 0.7)
                        recommendations.append({
                            "type": "reduce",
                            "interface": allocation.interface,
                            "application": allocation.application,
                            "current_allocation": allocated,
                            "recommended_allocation": new_allocation,
                            "savings_mbps": allocated - new_allocation,
                            "reason": f"Under-utilized: {usage_ratio:.1%} usage"
                        })
                    
                    elif usage_ratio > 0.8:  # Over-utilized
                        new_allocation = min(current_usage * 1.3, allocated * 1.5)
                        recommendations.append({
                            "type": "increase",
                            "interface": allocation.interface,
                            "application": allocation.application,
                            "current_allocation": allocated,
                            "recommended_allocation": new_allocation,
                            "additional_mbps": new_allocation - allocated,
                            "reason": f"Over-utilized: {usage_ratio:.1%} usage"
                        })
            
            # Calculate potential savings
            total_savings = sum(r.get("savings_mbps", 0) for r in recommendations)
            total_additional = sum(r.get("additional_mbps", 0) for r in recommendations)
            
            return {
                "recommendations": recommendations,
                "total_recommendations": len(recommendations),
                "potential_savings_mbps": total_savings,
                "additional_needed_mbps": total_additional,
                "net_savings_mbps": total_savings - total_additional,
                "timestamp": datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error optimizing allocations: {e}")
            return {"error": str(e)}
    
    def apply_optimization(self, recommendations: List[Dict]) -> Dict:
        """Apply optimization recommendations"""
        applied = []
        failed = []
        
        for rec in recommendations:
            try:
                success = self.modify_allocation(
                    interface=rec["interface"],
                    application=rec["application"],
                    priority="normal",  # Assume normal priority for now
                    new_allocated_mbps=rec["recommended_allocation"]
                )
                
                if success:
                    applied.append(rec)
                else:
                    failed.append(rec)
            
            except Exception as e:
                logger.error(f"Failed to apply recommendation: {e}")
                failed.append(rec)
        
        return {
            "applied": len(applied),
            "failed": len(failed),
            "applied_recommendations": applied,
            "failed_recommendations": failed,
            "timestamp": datetime.now().isoformat()
        }

if __name__ == "__main__":
    # Example usage
    manager = BandwidthManager()
    
    # Get available interfaces
    interfaces = manager.get_available_interfaces()
    print(f"Available interfaces: {interfaces}")
    
    if interfaces:
        interface = interfaces[0]
        print(f"Using interface: {interface}")
        
        # Create some allocations
        manager.create_allocation(interface, "Web Traffic", 50.0, "medium")
        manager.create_allocation(interface, "VoIP", 10.0, "high", min_guaranteed_mbps=5.0)
        manager.create_allocation(interface, "File Transfer", 30.0, "low")
        
        # Start monitoring
        manager.start_monitoring()
        
        try:
            # Let it run for a bit
            time.sleep(30)
            
            # Get statistics
            allocations = manager.get_allocations(interface)
            print(f"\nCurrent allocations: {len(allocations)}")
            
            for alloc in allocations:
                print(f"  {alloc['application']}: {alloc['allocated_mbps']}Mbps ({alloc['priority']} priority)")
            
            # Get summary
            summary = manager.get_bandwidth_summary()
            print(f"\nBandwidth Summary:")
            print(f"  Total Capacity: {summary['total_capacity_mbps']:.1f}Mbps")
            print(f"  Total Allocated: {summary['total_allocated_mbps']:.1f}Mbps")
            print(f"  Allocation Utilization: {summary['allocation_utilization_percent']:.1f}%")
            
        except KeyboardInterrupt:
            print("\nStopping...")
        finally:
            manager.stop_monitoring()