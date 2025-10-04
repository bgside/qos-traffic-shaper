# ⚡ QoS Traffic Shaper

**Enterprise-grade Quality of Service management system with intelligent bandwidth optimization**

[![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-v3.0+-green.svg)](https://flask.palletsprojects.com/)
[![Redis](https://img.shields.io/badge/redis-v5.0+-red.svg)](https://redis.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive QoS traffic management platform designed for enterprise networks. Features real-time traffic analysis, dynamic bandwidth allocation, intelligent policy enforcement, and AI-powered network optimization recommendations.

## 🌟 Features

### Core QoS Capabilities
- **🔍 Real-time Traffic Analysis** - Deep packet inspection and flow classification
- **📊 Dynamic Bandwidth Management** - Intelligent allocation and traffic shaping  
- **🛡️ Policy Engine** - Rule-based QoS enforcement with time-based conditions
- **📈 Network Monitoring** - Comprehensive health checks and performance metrics
- **🤖 AI Optimization** - Machine learning-powered performance recommendations
- **🌐 Web Dashboard** - Real-time monitoring with WebSocket updates

### Advanced Features
- **⚡ Linux Traffic Control Integration** - HTB queueing disciplines
- **🎯 Application-aware QoS** - Automatic service prioritization
- **📱 Real-time Analytics** - Live bandwidth and latency monitoring
- **🔄 Automatic Optimization** - Self-tuning network parameters
- **📊 Performance Reporting** - Detailed analytics and trend analysis
- **🔗 API Integration** - RESTful interface for network management systems

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Dashboard │    │   RESTful API   │    │  Traffic Engine │
│                 │    │                 │    │                 │
│ • Real-time UI  │    │ • Bandwidth API │    │ • Packet Analysis│
│ • QoS Policies  │◄──►│ • Policy CRUD   │◄──►│ • Flow Tracking │
│ • Performance   │    │ • Statistics    │    │ • Classification │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Bandwidth Manager│    │  Policy Engine  │    │Network Monitor │
│                 │    │                 │    │                 │
│ • Traffic Shaping│    │ • Rule Engine   │    │ • Health Checks │
│ • HTB Integration│    │ • Violations    │    │ • Diagnostics   │
│ • Auto Scaling  │    │ • Time-based    │    │ • Alerts        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Redis Server
- Linux system (for traffic control features)
- Administrator privileges (for network management)

### Installation

```bash
# Clone the repository
git clone https://github.com/bgside/qos-traffic-shaper.git
cd qos-traffic-shaper

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure Redis connection
# Edit config.yaml with your Redis settings

# Start the application
python app.py
```

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# Access the dashboard
http://localhost:5000
```

## 💻 Usage

### Web Dashboard
1. Navigate to `http://localhost:5000`
2. Configure network interfaces and bandwidth limits
3. Create QoS policies for different applications
4. Monitor real-time traffic and performance metrics
5. View optimization recommendations

### API Usage

```python
import requests

# Create bandwidth allocation
response = requests.post('http://localhost:5000/api/bandwidth/allocate', json={
    'interface': 'eth0',
    'application': 'Video Conferencing',
    'bandwidth_mbps': 50,
    'priority': 'high'
})

# Get traffic statistics
stats = requests.get('http://localhost:5000/api/traffic/stats')
print(f"Current bandwidth utilization: {stats.json()['utilization']}%")
```

### CLI Management

```bash
# View current traffic policies
curl http://localhost:5000/api/policies

# Start traffic shaping
curl -X POST http://localhost:5000/api/traffic/start

# Get optimization recommendations
curl http://localhost:5000/api/optimization/recommendations
```

## 🔧 Configuration

### Basic Configuration (`config.yaml`)

```yaml
# Server settings
server:
  host: "0.0.0.0"
  port: 5000
  debug: false

# Redis configuration
database:
  redis:
    host: "localhost"
    port: 6379

# QoS settings
qos:
  bandwidth_allocation:
    default_interface_speed: 1000  # Mbps
    reserve_percentage: 10
  
  traffic_shaping:
    enabled: true
    queue_algorithm: "htb"
```

### QoS Policies

```yaml
policies:
  high_priority:
    - "VoIP"
    - "Video Conferencing" 
    - "RDP"
    - "SSH"
  
  medium_priority:
    - "HTTP"
    - "HTTPS"
    - "DNS"
  
  low_priority:
    - "FTP"
    - "BitTorrent"
    - "Backup"
```

## 📊 Key Components

### 1. **Traffic Analyzer**
- Real-time packet capture using Scapy
- Deep packet inspection and application classification
- Flow tracking with bidirectional statistics
- Protocol analysis and bandwidth usage trends

### 2. **Bandwidth Manager** 
- Linux Traffic Control (tc) integration
- HTB (Hierarchical Token Bucket) queueing
- Dynamic bandwidth allocation
- Interface monitoring and capacity detection

### 3. **Policy Engine**
- Rule-based QoS policies with conditions and actions
- Time-based policies for business hours optimization
- Application-aware traffic prioritization
- Policy violation tracking and alerting

### 4. **Network Monitor**
- Multi-target connectivity testing
- Real-time latency and packet loss monitoring
- Interface statistics and error detection
- Automated network diagnostics

### 5. **Optimization Engine**
- Machine learning-based network analysis
- Intelligent bandwidth allocation recommendations
- Performance trend analysis with statistical modeling
- Automated optimization with confidence scoring

## 🔍 Monitoring & Analytics

### Real-time Metrics
- **Bandwidth Utilization**: Current usage vs. allocated capacity
- **Traffic Analysis**: Top applications, protocols, and flows
- **Network Health**: Latency, packet loss, and error rates
- **QoS Performance**: Policy effectiveness and violation tracking

### Performance Reports
```json
{
  "interface": "eth0",
  "utilization": 67.3,
  "allocated_bandwidth": 1000,
  "top_applications": [
    {"name": "Video Conferencing", "usage": 245.6, "priority": "high"},
    {"name": "Web Browsing", "usage": 156.2, "priority": "medium"}
  ],
  "qos_violations": 3,
  "recommendations": [
    "Increase video conferencing bandwidth allocation",
    "Implement stricter P2P traffic limits"
  ]
}
```

## 🎯 QoS Techniques

### Traffic Classification
- **Port-based**: Standard service ports (80, 443, 22, etc.)
- **Deep Packet Inspection**: Application signatures and patterns
- **Behavioral Analysis**: Traffic patterns and flow characteristics
- **Custom Rules**: User-defined classification criteria

### Traffic Shaping Methods
- **Hierarchical Token Bucket (HTB)**: Multi-class bandwidth allocation
- **Class-Based Queuing (CBQ)**: Priority-based traffic handling
- **Random Early Detection (RED)**: Congestion avoidance
- **Traffic Policing**: Rate limiting and burst control

### Priority Classes
- **Real-time (High)**: VoIP, video conferencing, gaming
- **Interactive (Medium)**: HTTP, SSH, DNS, email
- **Bulk (Low)**: FTP, backup, P2P, updates
- **Background**: Non-critical system traffic

## 🔌 Integrations

### Network Management
- **SNMP Integration**: Network device monitoring
- **Syslog Support**: Centralized logging
- **RADIUS/LDAP**: User-based policies
- **NetFlow/sFlow**: Advanced traffic analysis

### Enterprise Systems
- **Network Monitoring**: Nagios, Zabbix, PRTG integration
- **Ticketing**: Automatic incident creation
- **Reporting**: Executive dashboards and KPI tracking
- **APIs**: RESTful interface for third-party tools

## 📈 Performance Optimization

### Bandwidth Allocation Strategies
- **Guaranteed Minimum**: Reserve bandwidth for critical applications
- **Dynamic Scaling**: Automatic adjustment based on demand
- **Burst Allowance**: Temporary bandwidth increase for peak loads
- **Fair Queuing**: Equal distribution among competing flows

### Optimization Recommendations
```python
# Example optimization suggestions
recommendations = [
    {
        "type": "bandwidth_increase",
        "application": "Video Conferencing",
        "current": "50 Mbps",
        "recommended": "75 Mbps",
        "confidence": 0.85,
        "reason": "Consistent high utilization during business hours"
    }
]
```

## 🧪 Testing & Validation

### Performance Testing
```bash
# Run bandwidth tests
python -m pytest tests/test_bandwidth.py

# Load testing
python scripts/load_test.py --duration=300 --connections=100

# QoS policy validation
python scripts/validate_qos.py --interface=eth0
```

### Network Simulation
- **Traffic Generation**: Synthetic load testing
- **Scenario Testing**: Business hour vs. off-peak performance
- **Failover Testing**: Interface redundancy validation
- **Policy Testing**: QoS rule effectiveness measurement

## 🔒 Security & Compliance

### Security Features
- **Access Control**: Role-based dashboard access
- **Audit Logging**: All configuration changes tracked
- **Secure Communications**: HTTPS and API authentication
- **Network Isolation**: Management traffic separation

### Compliance Support
- **Traffic Auditing**: Detailed usage reports
- **Policy Enforcement**: Consistent rule application
- **Data Retention**: Configurable log retention policies
- **Regulatory Reporting**: Bandwidth usage documentation

## 📚 API Documentation

### Traffic Management
- `GET /api/traffic/stats` - Current traffic statistics
- `POST /api/traffic/start` - Start traffic shaping
- `POST /api/traffic/stop` - Stop traffic shaping
- `GET /api/traffic/flows` - Active traffic flows

### Bandwidth Management
- `POST /api/bandwidth/allocate` - Create bandwidth allocation
- `GET /api/bandwidth/allocations` - List all allocations
- `PUT /api/bandwidth/modify/{id}` - Modify allocation
- `DELETE /api/bandwidth/{id}` - Remove allocation

### Policy Management
- `GET /api/policies` - List QoS policies
- `POST /api/policies` - Create new policy
- `PUT /api/policies/{id}` - Update policy
- `DELETE /api/policies/{id}` - Delete policy

### Optimization
- `GET /api/optimization/recommendations` - Get recommendations
- `POST /api/optimization/apply` - Apply optimization
- `GET /api/optimization/history` - Optimization history

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Wiki](https://github.com/bgside/qos-traffic-shaper/wiki)
- **Issues**: [GitHub Issues](https://github.com/bgside/qos-traffic-shaper/issues)
- **Discussions**: [GitHub Discussions](https://github.com/bgside/qos-traffic-shaper/discussions)

## 🏆 Recognition

This project demonstrates enterprise-level network engineering expertise:
- Advanced QoS implementation and traffic engineering
- Linux networking and traffic control mastery
- Real-time system development and optimization
- Machine learning applications in network management
- Professional web application development

Perfect for network engineers, system administrators, and DevOps professionals seeking to showcase advanced networking and QoS expertise.

---

**⚡ Built for Enterprise Networks** | **🎯 Optimized for Performance** | **🔧 Production Ready**