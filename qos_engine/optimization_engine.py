"""
Optimization Engine Module
Network performance optimization and intelligent recommendations
"""
import json
import logging
import time
import statistics
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from threading import Thread, Lock, Event
from collections import defaultdict, deque
import numpy as np

logger = logging.getLogger(__name__)

@dataclass
class OptimizationRecommendation:
    """Optimization recommendation"""
    id: str
    type: str  # bandwidth, policy, routing, configuration
    title: str
    description: str
    impact: str  # low, medium, high
    effort: str  # low, medium, high
    priority_score: float
    target: str  # interface, application, policy
    current_value: Any
    recommended_value: Any
    estimated_improvement: str
    confidence: float
    created_at: datetime = None
    applied: bool = False
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class PerformanceMetric:
    """Performance metric data point"""
    metric_name: str
    value: float
    timestamp: datetime
    interface: Optional[str] = None
    application: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class OptimizationEngine:
    """Intelligent network optimization and recommendation engine"""
    
    def __init__(self):
        self.recommendations: Dict[str, OptimizationRecommendation] = {}
        self.performance_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.baseline_metrics: Dict[str, float] = {}
        self.optimization_rules: List[Dict] = []
        self._lock = Lock()
        self._analysis_active = False
        self._analysis_thread = None
        self._stop_event = Event()
        
        # Analysis configuration
        self.analysis_interval = 60  # seconds
        self.min_data_points = 10
        self.optimization_thresholds = {
            'bandwidth_utilization': 80.0,  # %
            'latency_threshold': 150.0,     # ms
            'packet_loss_threshold': 2.0,   # %
            'error_rate_threshold': 0.1     # %
        }
        
        # Load optimization rules
        self._load_optimization_rules()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def _load_optimization_rules(self):
        """Load optimization rules from configuration"""
        self.optimization_rules = [
            {
                'name': 'high_bandwidth_utilization',
                'condition': lambda metrics: metrics.get('bandwidth_util', 0) > 80,
                'recommendation_type': 'bandwidth',
                'generate_func': self._generate_bandwidth_recommendation
            },
            {
                'name': 'high_latency',
                'condition': lambda metrics: metrics.get('avg_latency', 0) > 150,
                'recommendation_type': 'routing',
                'generate_func': self._generate_latency_recommendation
            },
            {
                'name': 'packet_loss',
                'condition': lambda metrics: metrics.get('packet_loss', 0) > 2.0,
                'recommendation_type': 'configuration',
                'generate_func': self._generate_packet_loss_recommendation
            },
            {
                'name': 'unbalanced_traffic',
                'condition': lambda metrics: self._detect_traffic_imbalance(metrics),
                'recommendation_type': 'policy',
                'generate_func': self._generate_load_balancing_recommendation
            },
            {
                'name': 'inefficient_qos',
                'condition': lambda metrics: self._detect_qos_inefficiency(metrics),
                'recommendation_type': 'policy',
                'generate_func': self._generate_qos_optimization_recommendation
            }
        ]
    
    def start_analysis(self):
        """Start optimization analysis"""
        if self._analysis_active:
            logger.warning("Optimization analysis is already active")
            return
        
        self._analysis_active = True
        self._stop_event.clear()
        self._analysis_thread = Thread(target=self._analysis_loop, daemon=True)
        self._analysis_thread.start()
        
        logger.info("Started optimization analysis")
    
    def stop_analysis(self):
        """Stop optimization analysis"""
        if not self._analysis_active:
            return
        
        self._stop_event.set()
        self._analysis_active = False
        
        if self._analysis_thread and self._analysis_thread.is_alive():
            self._analysis_thread.join(timeout=5)
        
        logger.info("Stopped optimization analysis")
    
    def _analysis_loop(self):
        """Main analysis loop"""
        while not self._stop_event.is_set():
            try:
                # Analyze current performance
                self._analyze_performance()
                
                # Generate recommendations
                self._generate_recommendations()
                
                # Update baselines
                self._update_baselines()
                
                # Sleep for analysis interval
                time.sleep(self.analysis_interval)
                
            except Exception as e:
                logger.error(f"Error in analysis loop: {e}")
                time.sleep(self.analysis_interval)
    
    def add_performance_data(self, metric_name: str, value: float, 
                           interface: str = None, application: str = None):
        """Add performance data point"""
        try:
            metric = PerformanceMetric(
                metric_name=metric_name,
                value=value,
                timestamp=datetime.now(),
                interface=interface,
                application=application
            )
            
            key = f"{metric_name}_{interface or 'global'}_{application or 'all'}"
            
            with self._lock:
                self.performance_history[key].append(metric)
            
            logger.debug(f"Added performance data: {metric_name}={value}")
        
        except Exception as e:
            logger.error(f"Error adding performance data: {e}")
    
    def _analyze_performance(self):
        """Analyze current performance metrics"""
        try:
            with self._lock:
                current_metrics = {}
                
                # Calculate aggregate metrics
                for key, history in self.performance_history.items():
                    if len(history) >= self.min_data_points:
                        recent_values = [m.value for m in list(history)[-50:]]  # Last 50 points
                        
                        metric_name = key.split('_')[0]
                        interface = key.split('_')[1] if key.split('_')[1] != 'global' else None
                        
                        # Calculate statistics
                        current_metrics[key] = {
                            'current': recent_values[-1],
                            'average': statistics.mean(recent_values),
                            'median': statistics.median(recent_values),
                            'max': max(recent_values),
                            'min': min(recent_values),
                            'std_dev': statistics.stdev(recent_values) if len(recent_values) > 1 else 0,
                            'trend': self._calculate_trend(recent_values),
                            'interface': interface,
                            'metric_name': metric_name
                        }
                
                # Store current metrics for rule evaluation
                self.current_metrics = current_metrics
                
        except Exception as e:
            logger.error(f"Error analyzing performance: {e}")
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction from values"""
        if len(values) < 5:
            return "insufficient_data"
        
        try:
            # Use linear regression to determine trend
            x = np.arange(len(values))
            slope, _ = np.polyfit(x, values, 1)
            
            # Determine trend based on slope
            if abs(slope) < 0.1:
                return "stable"
            elif slope > 0:
                return "increasing"
            else:
                return "decreasing"
        
        except Exception:
            return "unknown"
    
    def _generate_recommendations(self):
        """Generate optimization recommendations based on rules"""
        try:
            if not hasattr(self, 'current_metrics'):
                return
            
            # Aggregate metrics for rule evaluation
            aggregated_metrics = self._aggregate_metrics()
            
            # Evaluate each rule
            for rule in self.optimization_rules:
                try:
                    if rule['condition'](aggregated_metrics):
                        recommendation = rule['generate_func'](aggregated_metrics)
                        if recommendation:
                            with self._lock:
                                self.recommendations[recommendation.id] = recommendation
                            
                            logger.info(f"Generated recommendation: {recommendation.title}")
                
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule['name']}: {e}")
        
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
    
    def _aggregate_metrics(self) -> Dict[str, float]:
        """Aggregate current metrics for rule evaluation"""
        aggregated = {}
        
        try:
            # Bandwidth utilization
            bandwidth_utils = [
                metrics['current'] for key, metrics in self.current_metrics.items()
                if 'bandwidth_util' in key
            ]
            if bandwidth_utils:
                aggregated['bandwidth_util'] = max(bandwidth_utils)
            
            # Latency
            latencies = [
                metrics['average'] for key, metrics in self.current_metrics.items()
                if 'latency' in key
            ]
            if latencies:
                aggregated['avg_latency'] = statistics.mean(latencies)
            
            # Packet loss
            packet_losses = [
                metrics['average'] for key, metrics in self.current_metrics.items()
                if 'packet_loss' in key
            ]
            if packet_losses:
                aggregated['packet_loss'] = max(packet_losses)
            
            # Error rates
            error_rates = [
                metrics['current'] for key, metrics in self.current_metrics.items()
                if 'error_rate' in key
            ]
            if error_rates:
                aggregated['error_rate'] = max(error_rates)
            
            # Throughput
            throughputs = [
                metrics['average'] for key, metrics in self.current_metrics.items()
                if 'throughput' in key
            ]
            if throughputs:
                aggregated['total_throughput'] = sum(throughputs)
            
        except Exception as e:
            logger.error(f"Error aggregating metrics: {e}")
        
        return aggregated
    
    def _detect_traffic_imbalance(self, metrics: Dict[str, float]) -> bool:
        """Detect traffic imbalance across interfaces"""
        try:
            interface_throughputs = {}
            
            for key, metric_data in self.current_metrics.items():
                if 'throughput' in key and metric_data.get('interface'):
                    interface = metric_data['interface']
                    throughput = metric_data['average']
                    interface_throughputs[interface] = throughput
            
            if len(interface_throughputs) < 2:
                return False
            
            throughput_values = list(interface_throughputs.values())
            max_throughput = max(throughput_values)
            min_throughput = min(throughput_values)
            
            # Consider imbalanced if ratio > 3:1
            return max_throughput / (min_throughput + 1) > 3
        
        except Exception:
            return False
    
    def _detect_qos_inefficiency(self, metrics: Dict[str, float]) -> bool:
        """Detect QoS policy inefficiency"""
        try:
            # Check if high priority traffic is experiencing issues
            high_priority_latency = metrics.get('high_priority_latency', 0)
            overall_latency = metrics.get('avg_latency', 0)
            
            # If high priority traffic has similar latency to overall average,
            # QoS might not be working effectively
            return high_priority_latency > overall_latency * 0.8
        
        except Exception:
            return False
    
    def _generate_bandwidth_recommendation(self, metrics: Dict[str, float]) -> OptimizationRecommendation:
        """Generate bandwidth optimization recommendation"""
        try:
            current_util = metrics.get('bandwidth_util', 0)
            recommendation_id = f"bandwidth_opt_{int(time.time())}"
            
            if current_util > 90:
                # Critical - immediate action needed
                return OptimizationRecommendation(
                    id=recommendation_id,
                    type="bandwidth",
                    title="Critical: Bandwidth Upgrade Required",
                    description=f"Bandwidth utilization at {current_util:.1f}% - immediate upgrade recommended",
                    impact="high",
                    effort="high",
                    priority_score=9.0,
                    target="infrastructure",
                    current_value=f"{current_util:.1f}%",
                    recommended_value="Upgrade link capacity",
                    estimated_improvement="50-80% performance improvement",
                    confidence=0.95
                )
            
            elif current_util > 80:
                # High - implement QoS
                return OptimizationRecommendation(
                    id=recommendation_id,
                    type="bandwidth",
                    title="Implement Advanced QoS Policies",
                    description=f"Bandwidth utilization at {current_util:.1f}% - optimize with traffic shaping",
                    impact="medium",
                    effort="medium",
                    priority_score=7.0,
                    target="qos_policies",
                    current_value=f"{current_util:.1f}%",
                    recommended_value="Target: <70% utilization",
                    estimated_improvement="20-40% efficiency gain",
                    confidence=0.85
                )
            
        except Exception as e:
            logger.error(f"Error generating bandwidth recommendation: {e}")
        
        return None
    
    def _generate_latency_recommendation(self, metrics: Dict[str, float]) -> OptimizationRecommendation:
        """Generate latency optimization recommendation"""
        try:
            current_latency = metrics.get('avg_latency', 0)
            recommendation_id = f"latency_opt_{int(time.time())}"
            
            if current_latency > 300:
                # Critical latency
                return OptimizationRecommendation(
                    id=recommendation_id,
                    type="routing",
                    title="Critical: High Latency Detected",
                    description=f"Average latency {current_latency:.1f}ms - investigate routing and network path",
                    impact="high",
                    effort="medium",
                    priority_score=8.5,
                    target="routing",
                    current_value=f"{current_latency:.1f}ms",
                    recommended_value="Target: <100ms",
                    estimated_improvement="60-80% latency reduction",
                    confidence=0.8
                )
            
            elif current_latency > 150:
                # Moderate latency
                return OptimizationRecommendation(
                    id=recommendation_id,
                    type="configuration",
                    title="Optimize Network Configuration",
                    description=f"Latency {current_latency:.1f}ms - tune network buffers and algorithms",
                    impact="medium",
                    effort="low",
                    priority_score=6.0,
                    target="configuration",
                    current_value=f"{current_latency:.1f}ms",
                    recommended_value="Target: <80ms",
                    estimated_improvement="30-50% latency reduction",
                    confidence=0.75
                )
        
        except Exception as e:
            logger.error(f"Error generating latency recommendation: {e}")
        
        return None
    
    def _generate_packet_loss_recommendation(self, metrics: Dict[str, float]) -> OptimizationRecommendation:
        """Generate packet loss optimization recommendation"""
        try:
            packet_loss = metrics.get('packet_loss', 0)
            recommendation_id = f"packet_loss_opt_{int(time.time())}"
            
            return OptimizationRecommendation(
                id=recommendation_id,
                type="configuration",
                title="Address Packet Loss Issues",
                description=f"Packet loss at {packet_loss:.2f}% - check network hardware and congestion",
                impact="high",
                effort="medium",
                priority_score=8.0,
                target="hardware",
                current_value=f"{packet_loss:.2f}%",
                recommended_value="Target: <0.5%",
                estimated_improvement="Eliminate connection issues",
                confidence=0.9
            )
        
        except Exception as e:
            logger.error(f"Error generating packet loss recommendation: {e}")
        
        return None
    
    def _generate_load_balancing_recommendation(self, metrics: Dict[str, float]) -> OptimizationRecommendation:
        """Generate load balancing recommendation"""
        try:
            recommendation_id = f"load_balance_opt_{int(time.time())}"
            
            return OptimizationRecommendation(
                id=recommendation_id,
                type="policy",
                title="Implement Load Balancing",
                description="Traffic imbalance detected - implement dynamic load balancing",
                impact="medium",
                effort="medium",
                priority_score=6.5,
                target="load_balancing",
                current_value="Unbalanced traffic distribution",
                recommended_value="Equal distribution across interfaces",
                estimated_improvement="25-40% throughput improvement",
                confidence=0.7
            )
        
        except Exception as e:
            logger.error(f"Error generating load balancing recommendation: {e}")
        
        return None
    
    def _generate_qos_optimization_recommendation(self, metrics: Dict[str, float]) -> OptimizationRecommendation:
        """Generate QoS optimization recommendation"""
        try:
            recommendation_id = f"qos_opt_{int(time.time())}"
            
            return OptimizationRecommendation(
                id=recommendation_id,
                type="policy",
                title="Optimize QoS Policies",
                description="QoS inefficiency detected - review and optimize traffic prioritization",
                impact="medium",
                effort="low",
                priority_score=5.5,
                target="qos_policies",
                current_value="Suboptimal QoS performance",
                recommended_value="Optimized priority assignments",
                estimated_improvement="15-30% latency improvement for critical traffic",
                confidence=0.75
            )
        
        except Exception as e:
            logger.error(f"Error generating QoS recommendation: {e}")
        
        return None
    
    def _update_baselines(self):
        """Update performance baselines"""
        try:
            with self._lock:
                for key, history in self.performance_history.items():
                    if len(history) >= 50:  # Need sufficient data
                        values = [m.value for m in list(history)[-100:]]
                        baseline = statistics.median(values)
                        self.baseline_metrics[key] = baseline
        
        except Exception as e:
            logger.error(f"Error updating baselines: {e}")
    
    def get_recommendations(self, limit: int = None, type_filter: str = None) -> List[Dict]:
        """Get optimization recommendations"""
        recommendations = []
        
        with self._lock:
            for rec in self.recommendations.values():
                if type_filter and rec.type != type_filter:
                    continue
                
                data = asdict(rec)
                if data['created_at']:
                    data['created_at'] = data['created_at'].isoformat()
                recommendations.append(data)
        
        # Sort by priority score (descending)
        recommendations.sort(key=lambda x: x['priority_score'], reverse=True)
        
        if limit:
            recommendations = recommendations[:limit]
        
        return recommendations
    
    def apply_recommendation(self, recommendation_id: str) -> bool:
        """Mark recommendation as applied"""
        try:
            with self._lock:
                if recommendation_id in self.recommendations:
                    self.recommendations[recommendation_id].applied = True
                    logger.info(f"Marked recommendation {recommendation_id} as applied")
                    return True
                else:
                    logger.error(f"Recommendation {recommendation_id} not found")
                    return False
        
        except Exception as e:
            logger.error(f"Error applying recommendation: {e}")
            return False
    
    def dismiss_recommendation(self, recommendation_id: str) -> bool:
        """Dismiss a recommendation"""
        try:
            with self._lock:
                if recommendation_id in self.recommendations:
                    del self.recommendations[recommendation_id]
                    logger.info(f"Dismissed recommendation {recommendation_id}")
                    return True
                else:
                    logger.error(f"Recommendation {recommendation_id} not found")
                    return False
        
        except Exception as e:
            logger.error(f"Error dismissing recommendation: {e}")
            return False
    
    def get_performance_analysis(self, metric_name: str = None, 
                               interface: str = None, hours: int = 24) -> Dict:
        """Get performance analysis for specific metric"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            analysis = {
                'metric_name': metric_name,
                'interface': interface,
                'time_range_hours': hours,
                'data_points': 0,
                'current_value': 0,
                'average': 0,
                'min': 0,
                'max': 0,
                'trend': 'unknown',
                'baseline_comparison': 'unknown',
                'timestamp': datetime.now().isoformat()
            }
            
            with self._lock:
                # Find matching metrics
                matching_keys = []
                for key in self.performance_history.keys():
                    key_parts = key.split('_')
                    if (not metric_name or metric_name in key) and \
                       (not interface or interface in key):
                        matching_keys.append(key)
                
                if not matching_keys:
                    return analysis
                
                # Use first matching key for detailed analysis
                key = matching_keys[0]
                history = self.performance_history[key]
                
                # Filter by time range
                recent_data = [
                    m for m in history 
                    if m.timestamp >= cutoff_time
                ]
                
                if recent_data:
                    values = [m.value for m in recent_data]
                    
                    analysis.update({
                        'data_points': len(values),
                        'current_value': values[-1],
                        'average': statistics.mean(values),
                        'min': min(values),
                        'max': max(values),
                        'trend': self._calculate_trend(values)
                    })
                    
                    # Compare to baseline
                    baseline = self.baseline_metrics.get(key)
                    if baseline:
                        current = values[-1]
                        if current > baseline * 1.1:
                            analysis['baseline_comparison'] = 'above_baseline'
                        elif current < baseline * 0.9:
                            analysis['baseline_comparison'] = 'below_baseline'
                        else:
                            analysis['baseline_comparison'] = 'within_baseline'
            
            return analysis
        
        except Exception as e:
            logger.error(f"Error getting performance analysis: {e}")
            return analysis
    
    def get_optimization_summary(self) -> Dict:
        """Get optimization summary and statistics"""
        try:
            summary = {
                'total_recommendations': len(self.recommendations),
                'applied_recommendations': 0,
                'pending_recommendations': 0,
                'critical_recommendations': 0,
                'recommendation_types': defaultdict(int),
                'priority_distribution': {'high': 0, 'medium': 0, 'low': 0},
                'performance_metrics_tracked': len(self.performance_history),
                'baseline_metrics': len(self.baseline_metrics),
                'timestamp': datetime.now().isoformat()
            }
            
            with self._lock:
                for rec in self.recommendations.values():
                    if rec.applied:
                        summary['applied_recommendations'] += 1
                    else:
                        summary['pending_recommendations'] += 1
                    
                    if rec.priority_score >= 8.0:
                        summary['critical_recommendations'] += 1
                    
                    summary['recommendation_types'][rec.type] += 1
                    
                    if rec.priority_score >= 7.0:
                        summary['priority_distribution']['high'] += 1
                    elif rec.priority_score >= 4.0:
                        summary['priority_distribution']['medium'] += 1
                    else:
                        summary['priority_distribution']['low'] += 1
            
            # Convert defaultdict to regular dict
            summary['recommendation_types'] = dict(summary['recommendation_types'])
            
            return summary
        
        except Exception as e:
            logger.error(f"Error getting optimization summary: {e}")
            return {'error': str(e)}
    
    def export_recommendations(self, filepath: str) -> bool:
        """Export recommendations to file"""
        try:
            recommendations = self.get_recommendations()
            with open(filepath, 'w') as f:
                json.dump(recommendations, f, indent=2)
            
            logger.info(f"Exported {len(recommendations)} recommendations to {filepath}")
            return True
        
        except Exception as e:
            logger.error(f"Error exporting recommendations: {e}")
            return False
    
    def clear_old_recommendations(self, days: int = 30):
        """Clear old recommendations"""
        cutoff_time = datetime.now() - timedelta(days=days)
        
        with self._lock:
            old_recs = [
                rec_id for rec_id, rec in self.recommendations.items()
                if rec.created_at < cutoff_time and rec.applied
            ]
            
            for rec_id in old_recs:
                del self.recommendations[rec_id]
        
        logger.info(f"Cleared {len(old_recs)} old recommendations")

if __name__ == "__main__":
    # Example usage
    engine = OptimizationEngine()
    
    print("Starting optimization engine...")
    engine.start_analysis()
    
    # Simulate some performance data
    print("Adding sample performance data...")
    for i in range(100):
        # Simulate bandwidth utilization
        engine.add_performance_data("bandwidth_util", 85.0 + (i % 20), interface="eth0")
        
        # Simulate latency
        engine.add_performance_data("latency", 120.0 + (i % 50), interface="eth0")
        
        # Simulate packet loss
        engine.add_performance_data("packet_loss", 1.5 + (i % 5) * 0.1)
        
        time.sleep(0.1)  # Small delay
    
    try:
        # Let it analyze for a bit
        time.sleep(10)
        
        # Get recommendations
        recommendations = engine.get_recommendations(limit=5)
        print(f"\nOptimization Recommendations: {len(recommendations)}")
        
        for rec in recommendations:
            print(f"  {rec['title']} (Priority: {rec['priority_score']:.1f})")
            print(f"    Impact: {rec['impact']}, Effort: {rec['effort']}")
            print(f"    {rec['description']}")
            print()
        
        # Get summary
        summary = engine.get_optimization_summary()
        print(f"Optimization Summary:")
        print(f"  Total Recommendations: {summary['total_recommendations']}")
        print(f"  Critical Recommendations: {summary['critical_recommendations']}")
        print(f"  Performance Metrics Tracked: {summary['performance_metrics_tracked']}")
    
    except KeyboardInterrupt:
        print("\nStopping optimization engine...")
    finally:
        engine.stop_analysis()