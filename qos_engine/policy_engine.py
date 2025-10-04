"""
Policy Engine Module
QoS policy management and enforcement
"""
import json
import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from threading import Thread, Lock, Event
from enum import Enum

logger = logging.getLogger(__name__)

class PolicyAction(Enum):
    ALLOW = "allow"
    DENY = "deny"
    LIMIT = "limit"
    PRIORITIZE = "prioritize"
    MARK = "mark"

class PolicyCondition(Enum):
    SRC_IP = "src_ip"
    DST_IP = "dst_ip"
    SRC_PORT = "src_port"
    DST_PORT = "dst_port"
    PROTOCOL = "protocol"
    APPLICATION = "application"
    TIME_RANGE = "time_range"
    BANDWIDTH_USAGE = "bandwidth_usage"
    USER_GROUP = "user_group"

@dataclass
class QoSPolicy:
    """QoS Policy definition"""
    id: str
    name: str
    description: str
    priority: int
    conditions: Dict[str, Any]
    actions: Dict[str, Any]
    enabled: bool = True
    created_at: datetime = None
    last_modified: datetime = None
    hit_count: int = 0
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.last_modified is None:
            self.last_modified = datetime.now()

@dataclass
class PolicyViolation:
    """Policy violation record"""
    policy_id: str
    policy_name: str
    violation_type: str
    source_ip: str
    destination_ip: str
    application: str
    description: str
    timestamp: datetime = None
    severity: str = "medium"
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class PolicyEngine:
    """QoS Policy Engine for rule management and enforcement"""
    
    def __init__(self):
        self.policies: Dict[str, QoSPolicy] = {}
        self.violations: List[PolicyViolation] = []
        self.active_policies: List[QoSPolicy] = []
        self._lock = Lock()
        self._enforcement_active = False
        self._enforcement_thread = None
        self._stop_event = Event()
        
        # Load existing policies
        self._load_policies()
        self._update_active_policies()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def _load_policies(self):
        """Load policies from file"""
        try:
            with open('qos_policies.json', 'r') as f:
                data = json.load(f)
            
            for policy_data in data:
                if policy_data.get('created_at'):
                    policy_data['created_at'] = datetime.fromisoformat(policy_data['created_at'])
                if policy_data.get('last_modified'):
                    policy_data['last_modified'] = datetime.fromisoformat(policy_data['last_modified'])
                
                policy = QoSPolicy(**policy_data)
                self.policies[policy.id] = policy
            
            logger.info(f"Loaded {len(self.policies)} policies")
        
        except FileNotFoundError:
            logger.info("No existing policies file found, starting fresh")
        except Exception as e:
            logger.error(f"Failed to load policies: {e}")
    
    def _save_policies(self):
        """Save policies to file"""
        try:
            policies_data = []
            for policy in self.policies.values():
                data = asdict(policy)
                if data['created_at']:
                    data['created_at'] = data['created_at'].isoformat()
                if data['last_modified']:
                    data['last_modified'] = data['last_modified'].isoformat()
                policies_data.append(data)
            
            with open('qos_policies.json', 'w') as f:
                json.dump(policies_data, f, indent=2)
            
            logger.debug(f"Saved {len(policies_data)} policies")
        
        except Exception as e:
            logger.error(f"Failed to save policies: {e}")
    
    def create_policy(self, name: str, description: str, priority: int,
                     conditions: Dict[str, Any], actions: Dict[str, Any]) -> str:
        """Create new QoS policy"""
        try:
            policy_id = f"policy_{int(time.time() * 1000)}"
            
            policy = QoSPolicy(
                id=policy_id,
                name=name,
                description=description,
                priority=priority,
                conditions=conditions,
                actions=actions
            )
            
            with self._lock:
                self.policies[policy_id] = policy
                self._save_policies()
                self._update_active_policies()
            
            logger.info(f"Created policy: {name} (ID: {policy_id})")
            return policy_id
        
        except Exception as e:
            logger.error(f"Failed to create policy: {e}")
            return ""
    
    def update_policy(self, policy_id: str, **updates) -> bool:
        """Update existing policy"""
        try:
            with self._lock:
                if policy_id not in self.policies:
                    logger.error(f"Policy not found: {policy_id}")
                    return False
                
                policy = self.policies[policy_id]
                
                for key, value in updates.items():
                    if hasattr(policy, key):
                        setattr(policy, key, value)
                
                policy.last_modified = datetime.now()
                self._save_policies()
                self._update_active_policies()
            
            logger.info(f"Updated policy: {policy_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to update policy: {e}")
            return False
    
    def delete_policy(self, policy_id: str) -> bool:
        """Delete policy"""
        try:
            with self._lock:
                if policy_id not in self.policies:
                    logger.error(f"Policy not found: {policy_id}")
                    return False
                
                del self.policies[policy_id]
                self._save_policies()
                self._update_active_policies()
            
            logger.info(f"Deleted policy: {policy_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to delete policy: {e}")
            return False
    
    def get_policy(self, policy_id: str) -> Optional[Dict]:
        """Get policy by ID"""
        with self._lock:
            if policy_id in self.policies:
                policy = self.policies[policy_id]
                data = asdict(policy)
                if data['created_at']:
                    data['created_at'] = data['created_at'].isoformat()
                if data['last_modified']:
                    data['last_modified'] = data['last_modified'].isoformat()
                return data
        return None
    
    def get_all_policies(self) -> List[Dict]:
        """Get all policies"""
        policies = []
        with self._lock:
            for policy in self.policies.values():
                data = asdict(policy)
                if data['created_at']:
                    data['created_at'] = data['created_at'].isoformat()
                if data['last_modified']:
                    data['last_modified'] = data['last_modified'].isoformat()
                policies.append(data)
        
        # Sort by priority
        policies.sort(key=lambda x: x['priority'])
        return policies
    
    def _update_active_policies(self):
        """Update list of active policies"""
        with self._lock:
            self.active_policies = [
                policy for policy in self.policies.values() 
                if policy.enabled
            ]
            # Sort by priority (lower number = higher priority)
            self.active_policies.sort(key=lambda x: x.priority)
        
        logger.debug(f"Updated active policies: {len(self.active_policies)} enabled")
    
    def evaluate_flow(self, flow_data: Dict) -> List[Dict]:
        """Evaluate flow against all policies"""
        matching_policies = []
        
        with self._lock:
            for policy in self.active_policies:
                if self._matches_policy(flow_data, policy):
                    policy.hit_count += 1
                    matching_policies.append({
                        'policy_id': policy.id,
                        'policy_name': policy.name,
                        'actions': policy.actions,
                        'priority': policy.priority
                    })
        
        return matching_policies
    
    def _matches_policy(self, flow_data: Dict, policy: QoSPolicy) -> bool:
        """Check if flow matches policy conditions"""
        try:
            conditions = policy.conditions
            
            # Check IP conditions
            if 'src_ip' in conditions:
                if not self._match_ip(flow_data.get('src_ip', ''), conditions['src_ip']):
                    return False
            
            if 'dst_ip' in conditions:
                if not self._match_ip(flow_data.get('dst_ip', ''), conditions['dst_ip']):
                    return False
            
            # Check port conditions
            if 'src_port' in conditions:
                if not self._match_port(flow_data.get('src_port', 0), conditions['src_port']):
                    return False
            
            if 'dst_port' in conditions:
                if not self._match_port(flow_data.get('dst_port', 0), conditions['dst_port']):
                    return False
            
            # Check protocol
            if 'protocol' in conditions:
                if flow_data.get('protocol', '').lower() != conditions['protocol'].lower():
                    return False
            
            # Check application
            if 'application' in conditions:
                if not self._match_application(flow_data.get('application', ''), conditions['application']):
                    return False
            
            # Check time range
            if 'time_range' in conditions:
                if not self._match_time_range(conditions['time_range']):
                    return False
            
            # Check bandwidth usage
            if 'bandwidth_usage' in conditions:
                if not self._match_bandwidth(flow_data.get('bytes_per_sec', 0), conditions['bandwidth_usage']):
                    return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error matching policy {policy.id}: {e}")
            return False
    
    def _match_ip(self, ip: str, condition: str) -> bool:
        """Match IP address against condition"""
        if condition == "*" or condition == "any":
            return True
        
        # Support CIDR notation (simplified)
        if "/" in condition:
            # For full implementation, use ipaddress module
            network, prefix = condition.split("/")
            # Simplified check - just match network portion
            return ip.startswith(network.rsplit(".", int(4 - int(prefix) // 8))[0])
        
        return ip == condition
    
    def _match_port(self, port: int, condition) -> bool:
        """Match port against condition"""
        if isinstance(condition, str):
            if condition == "*" or condition == "any":
                return True
            if "-" in condition:
                # Port range
                start, end = map(int, condition.split("-"))
                return start <= port <= end
            return port == int(condition)
        
        return port == condition
    
    def _match_application(self, app: str, condition: str) -> bool:
        """Match application against condition"""
        if condition == "*" or condition == "any":
            return True
        
        condition_lower = condition.lower()
        app_lower = app.lower()
        
        # Support wildcards
        if "*" in condition_lower:
            pattern = condition_lower.replace("*", "")
            return pattern in app_lower
        
        return app_lower == condition_lower
    
    def _match_time_range(self, condition: Dict) -> bool:
        """Match current time against time range condition"""
        try:
            now = datetime.now()
            current_time = now.time()
            current_day = now.strftime("%A").lower()
            
            # Check days
            if 'days' in condition:
                allowed_days = [day.lower() for day in condition['days']]
                if current_day not in allowed_days:
                    return False
            
            # Check time range
            if 'start_time' in condition and 'end_time' in condition:
                start_time = datetime.strptime(condition['start_time'], "%H:%M").time()
                end_time = datetime.strptime(condition['end_time'], "%H:%M").time()
                
                if start_time <= end_time:
                    return start_time <= current_time <= end_time
                else:
                    # Overnight range
                    return current_time >= start_time or current_time <= end_time
            
            return True
        
        except Exception as e:
            logger.error(f"Error matching time range: {e}")
            return False
    
    def _match_bandwidth(self, usage: float, condition: Dict) -> bool:
        """Match bandwidth usage against condition"""
        try:
            operator = condition.get('operator', '>')
            threshold = condition.get('threshold', 0)
            
            if operator == '>':
                return usage > threshold
            elif operator == '<':
                return usage < threshold
            elif operator == '>=':
                return usage >= threshold
            elif operator == '<=':
                return usage <= threshold
            elif operator == '==':
                return usage == threshold
            
            return False
        
        except Exception as e:
            logger.error(f"Error matching bandwidth: {e}")
            return False
    
    def apply_policy_actions(self, flow_data: Dict, policy_actions: List[Dict]) -> Dict:
        """Apply policy actions to flow"""
        result = {
            'allowed': True,
            'priority': 'normal',
            'bandwidth_limit': None,
            'dscp_mark': None,
            'actions_applied': []
        }
        
        for policy_action in policy_actions:
            actions = policy_action['actions']
            
            # Process each action
            for action_type, action_value in actions.items():
                if action_type == 'allow':
                    result['allowed'] = action_value
                    result['actions_applied'].append(f"allow: {action_value}")
                
                elif action_type == 'deny':
                    if action_value:
                        result['allowed'] = False
                        result['actions_applied'].append("deny: true")
                
                elif action_type == 'priority':
                    result['priority'] = action_value
                    result['actions_applied'].append(f"priority: {action_value}")
                
                elif action_type == 'bandwidth_limit':
                    result['bandwidth_limit'] = action_value
                    result['actions_applied'].append(f"bandwidth_limit: {action_value}Mbps")
                
                elif action_type == 'dscp_mark':
                    result['dscp_mark'] = action_value
                    result['actions_applied'].append(f"dscp_mark: {action_value}")
        
        return result
    
    def record_violation(self, policy_id: str, flow_data: Dict, violation_type: str, description: str):
        """Record policy violation"""
        try:
            policy = self.policies.get(policy_id)
            if not policy:
                return
            
            violation = PolicyViolation(
                policy_id=policy_id,
                policy_name=policy.name,
                violation_type=violation_type,
                source_ip=flow_data.get('src_ip', 'unknown'),
                destination_ip=flow_data.get('dst_ip', 'unknown'),
                application=flow_data.get('application', 'unknown'),
                description=description
            )
            
            self.violations.append(violation)
            
            # Keep only last 1000 violations
            if len(self.violations) > 1000:
                self.violations = self.violations[-1000:]
            
            logger.warning(f"Policy violation recorded: {description}")
        
        except Exception as e:
            logger.error(f"Failed to record violation: {e}")
    
    def get_violations(self, limit: int = 100) -> List[Dict]:
        """Get recent policy violations"""
        violations = []
        
        for violation in self.violations[-limit:]:
            data = asdict(violation)
            if data['timestamp']:
                data['timestamp'] = data['timestamp'].isoformat()
            violations.append(data)
        
        return violations
    
    def get_policy_statistics(self) -> Dict:
        """Get policy usage statistics"""
        total_policies = len(self.policies)
        enabled_policies = len(self.active_policies)
        total_hits = sum(p.hit_count for p in self.policies.values())
        
        # Top policies by hits
        top_policies = sorted(
            self.policies.values(),
            key=lambda x: x.hit_count,
            reverse=True
        )[:10]
        
        top_policy_stats = [
            {
                'id': p.id,
                'name': p.name,
                'hit_count': p.hit_count,
                'priority': p.priority
            }
            for p in top_policies
        ]
        
        # Violation statistics
        recent_violations = [v for v in self.violations if v.timestamp >= datetime.now() - timedelta(days=1)]
        violation_types = {}
        for violation in recent_violations:
            violation_types[violation.violation_type] = violation_types.get(violation.violation_type, 0) + 1
        
        return {
            'total_policies': total_policies,
            'enabled_policies': enabled_policies,
            'total_policy_hits': total_hits,
            'recent_violations': len(recent_violations),
            'violation_types': violation_types,
            'top_policies': top_policy_stats,
            'timestamp': datetime.now().isoformat()
        }
    
    def create_default_policies(self):
        """Create default QoS policies"""
        default_policies = [
            {
                'name': 'High Priority VoIP',
                'description': 'Prioritize VoIP traffic for real-time communication',
                'priority': 1,
                'conditions': {
                    'application': 'voip',
                    'dst_port': '5060-5065'
                },
                'actions': {
                    'priority': 'high',
                    'bandwidth_limit': 10,
                    'dscp_mark': 'EF'
                }
            },
            {
                'name': 'Video Conferencing Priority',
                'description': 'Prioritize video conferencing applications',
                'priority': 2,
                'conditions': {
                    'application': '*video*',
                    'bandwidth_usage': {'operator': '>', 'threshold': 1000000}
                },
                'actions': {
                    'priority': 'high',
                    'bandwidth_limit': 50
                }
            },
            {
                'name': 'Limit P2P Traffic',
                'description': 'Limit bandwidth for P2P applications',
                'priority': 10,
                'conditions': {
                    'application': '*torrent*'
                },
                'actions': {
                    'priority': 'low',
                    'bandwidth_limit': 5
                }
            },
            {
                'name': 'Business Hours Web Priority',
                'description': 'Higher priority for web traffic during business hours',
                'priority': 5,
                'conditions': {
                    'application': 'http*',
                    'time_range': {
                        'days': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
                        'start_time': '09:00',
                        'end_time': '17:00'
                    }
                },
                'actions': {
                    'priority': 'medium',
                    'bandwidth_limit': 20
                }
            }
        ]
        
        for policy_def in default_policies:
            policy_id = self.create_policy(
                name=policy_def['name'],
                description=policy_def['description'],
                priority=policy_def['priority'],
                conditions=policy_def['conditions'],
                actions=policy_def['actions']
            )
            
            if policy_id:
                logger.info(f"Created default policy: {policy_def['name']}")
    
    def export_policies(self, filepath: str) -> bool:
        """Export policies to file"""
        try:
            policies = self.get_all_policies()
            with open(filepath, 'w') as f:
                json.dump(policies, f, indent=2)
            
            logger.info(f"Exported {len(policies)} policies to {filepath}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to export policies: {e}")
            return False
    
    def import_policies(self, filepath: str) -> bool:
        """Import policies from file"""
        try:
            with open(filepath, 'r') as f:
                policies_data = json.load(f)
            
            imported_count = 0
            for policy_data in policies_data:
                # Remove ID to create new policy
                policy_data.pop('id', None)
                policy_data.pop('created_at', None)
                policy_data.pop('last_modified', None)
                policy_data.pop('hit_count', None)
                
                policy_id = self.create_policy(
                    name=policy_data['name'],
                    description=policy_data['description'],
                    priority=policy_data['priority'],
                    conditions=policy_data['conditions'],
                    actions=policy_data['actions']
                )
                
                if policy_id:
                    imported_count += 1
            
            logger.info(f"Imported {imported_count} policies from {filepath}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to import policies: {e}")
            return False

if __name__ == "__main__":
    # Example usage
    engine = PolicyEngine()
    
    # Create default policies if none exist
    if not engine.policies:
        print("Creating default policies...")
        engine.create_default_policies()
    
    # Example flow evaluation
    test_flow = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.50',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'tcp',
        'application': 'http',
        'bytes_per_sec': 500000
    }
    
    print(f"\nEvaluating test flow: {test_flow}")
    matching_policies = engine.evaluate_flow(test_flow)
    
    print(f"Matching policies: {len(matching_policies)}")
    for policy in matching_policies:
        print(f"  {policy['policy_name']} (Priority: {policy['priority']})")
    
    # Apply actions
    if matching_policies:
        result = engine.apply_policy_actions(test_flow, matching_policies)
        print(f"\nPolicy result: {result}")
    
    # Get statistics
    stats = engine.get_policy_statistics()
    print(f"\nPolicy Statistics:")
    print(f"  Total Policies: {stats['total_policies']}")
    print(f"  Enabled Policies: {stats['enabled_policies']}")
    print(f"  Total Hits: {stats['total_policy_hits']}")