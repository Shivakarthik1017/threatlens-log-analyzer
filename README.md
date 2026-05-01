# 🛡️ ThreatLens – Log Analyzer & Attack Detector

A browser-based security log analysis tool that detects potential attacks and suspicious activity in log files. Built with pure HTML, CSS, and Vanilla JavaScript — no external dependencies.

![ThreatLens Screenshot](https://via.placeholder.com/1200x600/0a0e1a/3b82f6?text=ThreatLens+Dashboard)

## ✨ Features

### 🔍 Log Analysis
- **Multi-format support** — Paste any text-based log data
- **Real-time detection** — Automatic analysis as you type (debounced)
- **Sample logs included** — One-click demo with realistic security events

### 🚨 Attack Detection
- **Brute Force Detection** — Identifies repeated failed login attempts from the same IP
- **Suspicious IP Activity** — Flags IPs with multiple security events
- **Keyword-based Alerts** — Detects critical and warning-level suspicious terms

### 📊 Visual Dashboard
- **Summary Cards** — Total alerts, critical/warning counts, affected IPs
- **Alerts Panel** — Detailed security alerts with descriptions
- **IP Tracker** — List of suspicious IPs with event counts
- **Color-coded Log Viewer** — Lines highlighted by severity (red/yellow/normal)

### 🎨 UI/UX
- Dark cybersecurity-themed interface
- Fully responsive (mobile & desktop)
- Smooth animations and transitions
- Keyboard shortcuts (Ctrl+Enter to analyze)

## 🚀 Quick Start

1. **Clone or download** this repository
2. **Open `index.html`** in any modern web browser
3. **Click "Load Sample Logs"** to see demo data
4. **Click "Analyze Logs"** to run the detection engine

No installation, no server, no dependencies required!

## 📁 Project Structure

```
threatlens-log-analyzer/
├── index.html      # Main HTML structure
├── style.css       # Dark theme styling (CSS variables, responsive)
├── script.js       # Core analysis engine (parse, detect, highlight)
└── README.md       # This file
```

## 🧠 Detection Logic

### Severity Levels

| Level | Color | Keywords |
|-------|-------|----------|
| **Critical** | 🔴 Red | `failed login`, `authentication failed`, `unauthorized`, `brute force`, `intrusion`, `malware`, `injection`, `privilege escalation` |
| **Warning** | 🟡 Yellow | `failed`, `error`, `denied`, `rejected`, `suspicious`, `anomaly`, `blocked`, `timeout` |
| **Normal** | ⚪ Gray | All other log entries |

### Pattern Detection Thresholds

| Pattern | Threshold | Alert Type |
|---------|-----------|------------|
| Brute Force | 3+ failed logins from same IP | Critical |
| Suspicious IP | 3+ suspicious events from same IP (non-login) | Warning |
| High-Activity IP | 5+ total occurrences with critical events | Critical |

## 🛠️ Technical Details

### Core Functions

- **`parseLogs(logText)`** — Splits log text into structured entries, extracts IPs, matches keywords
- **`detectPatterns(parsedLogs)`** — Analyzes IP statistics, identifies brute force & suspicious activity
- **`highlightThreats(parsedLogs)`** — Renders color-coded log viewer with line numbers
- **`renderAlerts(alerts)`** — Displays security alerts with animations
- **`renderIPs(ips)`** — Shows suspicious IP tags with counts
- **`updateSummary(summary)`** — Animates dashboard counters

### Design Decisions

- **No frameworks** — Pure vanilla JS for maximum compatibility and performance
- **CSS Variables** — Easy theming and consistent color palette
- **Debounced input** — Real-time analysis without performance impact
- **Map-based IP tracking** — Efficient O(n) pattern detection

## 🌐 Browser Compatibility

- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+

## 📝 Usage Examples

### Analyzing Custom Logs

1. Copy your server/auth/security logs
2. Paste into the textarea
3. Click "Analyze Logs" or press `Ctrl+Enter`
4. Review alerts and highlighted log entries

### Sample Log Format

```
2024-01-15 08:30:22 WARNING: Failed login attempt for user 'admin' from 10.0.0.15
2024-01-15 08:31:18 ERROR: Authentication failed for user 'root' from 10.0.0.15
2024-01-15 08:40:12 WARNING: Unauthorized access attempt from 172.16.0.25
```

The analyzer automatically extracts IPs, detects patterns, and highlights threats.

## 🔮 Future Enhancements

- [ ] Export analysis reports (PDF/JSON)
- [ ] Custom keyword/threshold configuration
- [ ] Support for multiple log formats (Apache, Nginx, Windows Event Log)
- [ ] Historical analysis comparison
- [ ] Real-time log streaming via WebSocket
- [ ] GeoIP lookup for suspicious IPs
- [ ] Attack timeline visualization

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

MIT License — Feel free to use, modify, and distribute for personal or commercial projects.

## 🙏 Acknowledgments

- Inspired by real-world SIEM (Security Information and Event Management) systems
- Built for educational purposes to demonstrate log analysis concepts
- Designed with a modern cybersecurity aesthetic

---

**Built with ❤️ using Vanilla JavaScript**

[🔗 GitHub Repository](https://github.com/Shivakarthik1017/threatlens-log-analyzer)