#!/usr/bin/env python3
"""
QoS Traffic Shaper - Quality of Service Management System
Enterprise network bandwidth optimization with traffic analysis

Author: Ali Emad SALEH
GitHub: https://github.com/bgside
LinkedIn: https://www.linkedin.com/in/hex41414141/
"""

from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
import sqlite3
from typing import Dict, List, Any, Optional

from qos_engine.traffic_analyzer import TrafficAnalyzer
from qos_engine.bandwidth_manager import BandwidthManager
from qos_engine.policy_engine import PolicyEngine
from qos_engine.network_monitor import NetworkMonitor
from qos_engine.optimization_engine import OptimizationEngine
from config.settings import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/qos_shaper.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize QoS components
traffic_analyzer = TrafficAnalyzer()
bandwidth_manager = BandwidthManager()
policy_engine = PolicyEngine()
network_monitor = NetworkMonitor()
optimization_engine = OptimizationEngine()

# Global state
active_policies = {}
traffic_stats = {}
shaping_active = False

@app.route('/')
def dashboard():
    """Main QoS dashboard"""
    return render_template('dashboard.html', shaping_active=shaping_active)

@app.route('/policies')
def policies():
    """QoS policies management page"""
    return render_template('policies.html')

@app.route('/analytics')
def analytics():
    """Traffic analytics page"""
    return render_template('analytics.html')

@app.route('/optimization')
def optimization():
    """Network optimization page"""
    return render_template('optimization.html')

@app.route('/api/traffic/stats', methods=['GET'])
def get_traffic_stats():
    """Get current traffic statistics"""
    try:
        interface = request.args.get('interface', 'all')
        timeframe = request.args.get('timeframe', '1h')
        
        stats = traffic_analyzer.get_traffic_stats(interface, timeframe)
        
        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting traffic stats: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/traffic/analysis', methods=['POST'])
def analyze_traffic():
    """Perform traffic analysis"""
    try:
        analysis_config = request.json
        
        # Validate configuration
        required_fields = ['interface', 'duration', 'analysis_type']
        for field in required_fields:
            if field not in analysis_config:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        # Start traffic analysis
        analysis_id = traffic_analyzer.start_analysis(analysis_config)
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'message': 'Traffic analysis started'
        })
        
    except Exception as e:
        logger.error(f"Error starting traffic analysis: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/bandwidth/allocation', methods=['GET'])
def get_bandwidth_allocation():
    """Get current bandwidth allocation"""
    try:
        allocations = bandwidth_manager.get_allocations()
        
        return jsonify({
            'success': True,
            'allocations': allocations,
            'total_capacity': bandwidth_manager.get_total_capacity(),
            'utilization': bandwidth_manager.get_utilization()
        })
        
    except Exception as e:
        logger.error(f"Error getting bandwidth allocation: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/bandwidth/configure', methods=['POST'])
def configure_bandwidth():
    """Configure bandwidth allocation"""
    try:
        bandwidth_config = request.json
        
        # Validate configuration
        if 'policies' not in bandwidth_config:
            return jsonify({
                'success': False,
                'error': 'Missing bandwidth policies'
            }), 400
        
        # Apply bandwidth configuration
        result = bandwidth_manager.configure_bandwidth(bandwidth_config['policies'])
        
        if result['success']:
            # Emit real-time update
            socketio.emit('bandwidth_updated', {
                'allocations': bandwidth_manager.get_allocations(),
                'timestamp': datetime.now().isoformat()
            })
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error configuring bandwidth: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/policies', methods=['GET'])
def get_policies():
    """Get all QoS policies"""
    try:
        policies = policy_engine.get_policies()
        
        return jsonify({
            'success': True,
            'policies': policies,
            'active_count': len([p for p in policies if p.get('active', False)])
        })
        
    except Exception as e:
        logger.error(f"Error getting policies: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/policies', methods=['POST'])
def create_policy():
    """Create new QoS policy"""
    try:
        policy_data = request.json
        
        # Validate policy
        validation_result = policy_engine.validate_policy(policy_data)
        if not validation_result['valid']:
            return jsonify({
                'success': False,
                'error': f'Invalid policy: {validation_result["errors"]}'
            }), 400
        
        # Create policy
        policy_id = policy_engine.create_policy(policy_data)
        
        return jsonify({
            'success': True,
            'policy_id': policy_id,
            'message': 'QoS policy created successfully'
        })
        
    except Exception as e:
        logger.error(f"Error creating policy: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/policies/<policy_id>', methods=['PUT'])
def update_policy(policy_id):
    """Update QoS policy"""
    try:
        policy_data = request.json
        
        # Validate policy
        validation_result = policy_engine.validate_policy(policy_data)
        if not validation_result['valid']:
            return jsonify({
                'success': False,
                'error': f'Invalid policy: {validation_result["errors"]}'
            }), 400
        
        # Update policy
        result = policy_engine.update_policy(policy_id, policy_data)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error updating policy: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/policies/<policy_id>/activate', methods=['POST'])
def activate_policy(policy_id):
    """Activate QoS policy"""
    try:
        result = policy_engine.activate_policy(policy_id)
        
        if result['success']:
            # Apply policy to traffic shaper
            policy = policy_engine.get_policy(policy_id)
            bandwidth_manager.apply_policy(policy)
            
            # Update global state
            global active_policies
            active_policies[policy_id] = policy
            
            # Emit real-time update
            socketio.emit('policy_activated', {
                'policy_id': policy_id,
                'policy': policy,
                'timestamp': datetime.now().isoformat()
            })
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error activating policy: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/shaping/start', methods=['POST'])
def start_shaping():
    """Start traffic shaping"""
    try:
        shaping_config = request.json
        
        # Start traffic shaping
        result = bandwidth_manager.start_shaping(shaping_config)
        
        if result['success']:
            global shaping_active
            shaping_active = True
            
            # Start monitoring thread
            threading.Thread(target=monitoring_loop, daemon=True).start()
            
            # Emit real-time update
            socketio.emit('shaping_started', {
                'config': shaping_config,
                'timestamp': datetime.now().isoformat()
            })
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error starting traffic shaping: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/shaping/stop', methods=['POST'])
def stop_shaping():
    """Stop traffic shaping"""
    try:
        result = bandwidth_manager.stop_shaping()
        
        if result['success']:
            global shaping_active
            shaping_active = False
            
            # Emit real-time update
            socketio.emit('shaping_stopped', {
                'timestamp': datetime.now().isoformat()
            })
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error stopping traffic shaping: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/optimization/analyze', methods=['POST'])
def analyze_optimization():
    """Analyze network for optimization opportunities"""
    try:
        analysis_config = request.json
        
        # Start optimization analysis
        analysis_id = optimization_engine.start_analysis(analysis_config)
        
        return jsonify({
            'success': True,
            'analysis_id': analysis_id,
            'message': 'Optimization analysis started'
        })
        
    except Exception as e:
        logger.error(f"Error starting optimization analysis: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/optimization/recommendations', methods=['GET'])
def get_optimization_recommendations():
    """Get optimization recommendations"""
    try:
        recommendations = optimization_engine.get_recommendations()
        
        return jsonify({
            'success': True,
            'recommendations': recommendations,
            'count': len(recommendations)
        })
        
    except Exception as e:
        logger.error(f"Error getting recommendations: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/optimization/apply', methods=['POST'])
def apply_optimization():
    """Apply optimization recommendations"""
    try:
        optimization_config = request.json
        
        # Apply optimizations
        result = optimization_engine.apply_optimizations(optimization_config)
        
        if result['success']:
            # Update bandwidth allocation
            bandwidth_manager.update_from_optimization(result['changes'])
            
            # Emit real-time update
            socketio.emit('optimization_applied', {
                'optimizations': result['changes'],
                'timestamp': datetime.now().isoformat()
            })
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error applying optimization: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/network/interfaces', methods=['GET'])
def get_network_interfaces():
    """Get network interfaces"""
    try:
        interfaces = network_monitor.get_interfaces()
        
        return jsonify({
            'success': True,
            'interfaces': interfaces
        })
        
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/network/topology', methods=['GET'])
def get_network_topology():
    """Get network topology"""
    try:
        topology = network_monitor.get_topology()
        
        return jsonify({
            'success': True,
            'topology': topology
        })
        
    except Exception as e:
        logger.error(f"Error getting topology: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/reports/traffic', methods=['GET'])
def generate_traffic_report():
    """Generate traffic analysis report"""
    try:
        timeframe = request.args.get('timeframe', '24h')
        format_type = request.args.get('format', 'json')
        
        report = traffic_analyzer.generate_report(timeframe, format_type)
        
        return jsonify({
            'success': True,
            'report': report,
            'generated_at': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def monitoring_loop():
    """Background monitoring loop"""
    global traffic_stats
    
    while shaping_active:
        try:
            # Collect traffic statistics
            current_stats = traffic_analyzer.collect_real_time_stats()
            traffic_stats.update(current_stats)
            
            # Check for policy violations
            violations = policy_engine.check_violations(current_stats)
            if violations:
                socketio.emit('policy_violations', {
                    'violations': violations,
                    'timestamp': datetime.now().isoformat()
                })
            
            # Update bandwidth allocation if needed
            if optimization_engine.should_auto_optimize():
                recommendations = optimization_engine.get_auto_recommendations()
                if recommendations:
                    bandwidth_manager.apply_auto_optimizations(recommendations)
                    
                    socketio.emit('auto_optimization', {
                        'recommendations': recommendations,
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Emit real-time statistics
            socketio.emit('traffic_update', {
                'stats': current_stats,
                'utilization': bandwidth_manager.get_utilization(),
                'timestamp': datetime.now().isoformat()
            })
            
            time.sleep(5)  # Update every 5 seconds
            
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            time.sleep(30)  # Wait longer on error

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('status', {
        'message': 'Connected to QoS Traffic Shaper',
        'shaping_active': shaping_active
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('request_real_time_data')
def handle_real_time_request():
    """Handle request for real-time data"""
    try:
        current_stats = traffic_analyzer.collect_real_time_stats()
        emit('real_time_data', {
            'traffic_stats': current_stats,
            'bandwidth_allocation': bandwidth_manager.get_allocations(),
            'active_policies': len(active_policies),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error sending real-time data: {e}")

if __name__ == '__main__':
    # Ensure directories exist
    os.makedirs('logs', exist_ok=True)
    os.makedirs('data', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    # Initialize QoS components
    logger.info("Initializing QoS Traffic Shaper")
    
    try:
        # Initialize traffic analyzer
        traffic_analyzer.initialize()
        logger.info("Traffic analyzer initialized")
        
        # Initialize bandwidth manager
        bandwidth_manager.initialize()
        logger.info("Bandwidth manager initialized")
        
        # Initialize policy engine
        policy_engine.initialize()
        logger.info("Policy engine initialized")
        
        # Initialize network monitor
        network_monitor.initialize()
        logger.info("Network monitor initialized")
        
        # Initialize optimization engine
        optimization_engine.initialize()
        logger.info("Optimization engine initialized")
        
        logger.info("QoS Traffic Shaper initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize QoS Traffic Shaper: {e}")
        exit(1)
    
    # Start the application
    logger.info("Starting QoS Traffic Shaper web server")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)