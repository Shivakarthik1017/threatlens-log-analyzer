/**
 * ThreatLens – Log Analyzer & Attack Detector
 * Pure Vanilla JavaScript implementation
 */

// ============================================
// Configuration & Constants
// ============================================

const CONFIG = {
    // Suspicious keywords with severity levels
    suspiciousKeywords: {
        // Critical severity
        critical: [
            'failed login',
            'authentication failed',
            'unauthorized',
            'access denied',
            'brute force',
            'intrusion',
            'malware',
            'exploit',
            'injection',
            'overflow',
            'privilege escalation'
        ],
        // Warning severity
        warning: [
            'failed',
            'error',
            'denied',
            'rejected',
            'invalid',
            'suspicious',
            'anomaly',
            'timeout',
            'blocked',
            'violation'
        ]
    },
    // Thresholds for pattern detection
    thresholds: {
        bruteForce: 3,      // 3+ failed logins from same IP
        suspiciousIP: 3,    // 3+ suspicious events from same IP
        repeatedIP: 5       // 5+ occurrences of same IP
    }
};

// Sample log data for demonstration
const SAMPLE_LOGS = `2024-01-15 08:23:45 INFO: System startup completed successfully
2024-01-15 08:25:12 INFO: User admin logged in from 192.168.1.50
2024-01-15 08:30:22 WARNING: Failed login attempt for user 'admin' from 10.0.0.15
2024-01-15 08:30:45 WARNING: Failed login attempt for user 'admin' from 10.0.0.15
2024-01-15 08:31:02 WARNING: Failed login attempt for user 'admin' from 10.0.0.15
2024-01-15 08:31:18 ERROR: Authentication failed for user 'root' from 10.0.0.15
2024-01-15 08:31:35 ERROR: Authentication failed for user 'root' from 10.0.0.15
2024-01-15 08:32:01 ALERT: Possible brute force attack detected from 10.0.0.15
2024-01-15 08:35:44 INFO: User jsmith logged in from 192.168.1.100
2024-01-15 08:40:12 WARNING: Unauthorized access attempt to /admin/panel from 172.16.0.25
2024-01-15 08:40:33 ERROR: Access denied for user 'guest' to resource '/etc/passwd' from 172.16.0.25
2024-01-15 08:41:05 WARNING: Suspicious request blocked from 172.16.0.25
2024-01-15 08:45:22 INFO: Database backup completed successfully
2024-01-15 09:00:15 INFO: User mwilson logged in from 192.168.1.75
2024-01-15 09:05:33 WARNING: Failed login attempt for user 'mwilson' from 203.0.113.42
2024-01-15 09:05:48 WARNING: Failed login attempt for user 'mwilson' from 203.0.113.42
2024-01-15 09:06:02 ERROR: Authentication failed for user 'admin' from 203.0.113.42
2024-01-15 09:06:15 ERROR: Authentication failed for user 'root' from 203.0.113.42
2024-01-15 09:10:44 INFO: Firewall rule updated by admin
2024-01-15 09:15:22 WARNING: Invalid certificate detected from 198.51.100.10
2024-01-15 09:20:18 ERROR: Connection timeout to external API
2024-01-15 09:25:33 WARNING: Rejected connection from 10.0.0.15 - IP blocked
2024-01-15 09:30:00 INFO: System health check passed
2024-01-15 09:35:12 WARNING: Failed login attempt for user 'dbadmin' from 10.0.0.15
2024-01-15 09:35:28 ERROR: Authentication failed for user 'dbadmin' from 10.0.0.15
2024-01-15 09:40:55 ALERT: Intrusion detection system triggered - potential SQL injection from 172.16.0.25
2024-01-15 09:45:11 INFO: User jsmith logged out
2024-01-15 09:50:22 WARNING: Anomaly detected in network traffic from 198.51.100.10
2024-01-15 10:00:00 INFO: Scheduled security scan initiated
2024-01-15 10:05:33 ERROR: Malware signature detected in uploaded file from 198.51.100.10
2024-01-15 10:10:45 WARNING: Privilege escalation attempt blocked from 10.0.0.15
2024-01-15 10:15:00 INFO: Security scan completed - 3 threats neutralized`;

// ============================================
// State Management
// ============================================

let analysisResults = null;

// ============================================
// DOM Elements
// ============================================

const elements = {
    logInput: document.getElementById('logInput'),
    sampleBtn: document.getElementById('sampleBtn'),
    analyzeBtn: document.getElementById('analyzeBtn'),
    clearBtn: document.getElementById('clearBtn'),
    resultsSection: document.getElementById('resultsSection'),
    viewerSection: document.getElementById('viewerSection'),
    alertsList: document.getElementById('alertsList'),
    ipsList: document.getElementById('ipsList'),
    logViewer: document.getElementById('logViewer'),
    totalAlerts: document.getElementById('totalAlerts'),
    criticalAlerts: document.getElementById('criticalAlerts'),
    warningAlerts: document.getElementById('warningAlerts'),
    affectedIPs: document.getElementById('affectedIPs')
};

// ============================================
// Core Functions
// ============================================

/**
 * Parse log input into structured data
 * @param {string} logText - Raw log text
 * @returns {Array} Array of parsed log entries
 */
function parseLogs(logText) {
    if (!logText || !logText.trim()) {
        return [];
    }

    const lines = logText.split('\n').filter(line => line.trim());
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

    return lines.map((line, index) => {
        const ips = line.match(ipRegex) || [];
        const lowerLine = line.toLowerCase();

        // Determine severity
        let severity = 'normal';
        let matchedKeywords = [];

        // Check critical keywords first
        for (const keyword of CONFIG.suspiciousKeywords.critical) {
            if (lowerLine.includes(keyword)) {
                severity = 'critical';
                matchedKeywords.push(keyword);
            }
        }

        // Check warning keywords (only if not already critical)
        if (severity === 'normal') {
            for (const keyword of CONFIG.suspiciousKeywords.warning) {
                if (lowerLine.includes(keyword)) {
                    severity = 'warning';
                    matchedKeywords.push(keyword);
                    break;
                }
            }
        }

        return {
            lineNumber: index + 1,
            raw: line,
            ips: ips,
            severity: severity,
            matchedKeywords: matchedKeywords
        };
    });
}

/**
 * Detect patterns in parsed logs
 * @param {Array} parsedLogs - Array of parsed log entries
 * @returns {Object} Detection results including alerts and statistics
 */
function detectPatterns(parsedLogs) {
    const alerts = [];
    const ipStats = new Map();
    const ipFailedLogins = new Map();
    const ipSuspiciousEvents = new Map();

    // Gather statistics
    parsedLogs.forEach(log => {
        // Track all IPs
        log.ips.forEach(ip => {
            const current = ipStats.get(ip) || { count: 0, severities: [] };
            current.count++;
            current.severities.push(log.severity);
            ipStats.set(ip, current);

            // Track failed logins per IP
            if (log.severity !== 'normal' && 
                (log.raw.toLowerCase().includes('failed login') || 
                 log.raw.toLowerCase().includes('authentication failed'))) {
                const failedCount = ipFailedLogins.get(ip) || 0;
                ipFailedLogins.set(ip, failedCount + 1);
            }

            // Track suspicious events per IP
            if (log.severity !== 'normal') {
                const suspCount = ipSuspiciousEvents.get(ip) || 0;
                ipSuspiciousEvents.set(ip, suspCount + 1);
            }
        });
    });

    // Detect brute force attacks
    ipFailedLogins.forEach((count, ip) => {
        if (count >= CONFIG.thresholds.bruteForce) {
            alerts.push({
                type: 'critical',
                title: '🔴 Possible Brute Force Attack',
                description: `IP address ${ip} has ${count} failed login attempts. This may indicate a brute force attack.`,
                ip: ip,
                count: count
            });
        }
    });

    // Detect suspicious IP activity
    ipSuspiciousEvents.forEach((count, ip) => {
        if (count >= CONFIG.thresholds.suspiciousIP && !ipFailedLogins.has(ip)) {
            alerts.push({
                type: 'warning',
                title: '🟡 Suspicious IP Activity Detected',
                description: `IP address ${ip} appears in ${count} suspicious events. Further investigation recommended.`,
                ip: ip,
                count: count
            });
        }
    });

    // Detect repeated IP occurrences
    ipStats.forEach((stats, ip) => {
        if (stats.count >= CONFIG.thresholds.repeatedIP) {
            const criticalCount = stats.severities.filter(s => s === 'critical').length;
            const warningCount = stats.severities.filter(s => s === 'warning').length;
            
            if (criticalCount > 0) {
                alerts.push({
                    type: 'critical',
                    title: '🔴 High-Activity Suspicious IP',
                    description: `IP ${ip} appears ${stats.count} times with ${criticalCount} critical and ${warningCount} warning events.`,
                    ip: ip,
                    count: stats.count
                });
            }
        }
    });

    // Collect affected IPs
    const affectedIPList = [];
    ipStats.forEach((stats, ip) => {
        if (stats.severities.some(s => s !== 'normal')) {
            const criticalCount = stats.severities.filter(s => s === 'critical').length;
            const warningCount = stats.severities.filter(s => s === 'warning').length;
            affectedIPList.push({
                ip: ip,
                totalCount: stats.count,
                criticalCount: criticalCount,
                warningCount: warningCount
            });
        }
    });

    // Sort affected IPs by critical count
    affectedIPList.sort((a, b) => b.criticalCount - a.criticalCount);

    // Calculate summary
    const criticalCount = alerts.filter(a => a.type === 'critical').length;
    const warningCount = alerts.filter(a => a.type === 'warning').length;

    return {
        alerts: alerts,
        affectedIPs: affectedIPList,
        summary: {
            totalAlerts: alerts.length,
            critical: criticalCount,
            warning: warningCount,
            affectedIPCount: affectedIPList.length,
            totalLines: parsedLogs.length,
            suspiciousLines: parsedLogs.filter(l => l.severity !== 'normal').length
        }
    };
}

/**
 * Highlight threats in the log viewer
 * @param {Array} parsedLogs - Array of parsed log entries
 */
function highlightThreats(parsedLogs) {
    const logViewer = elements.logViewer;
    logViewer.innerHTML = '';

    parsedLogs.forEach(log => {
        const lineDiv = document.createElement('div');
        lineDiv.className = `log-line ${log.severity}`;

        const lineNumber = document.createElement('span');
        lineNumber.className = 'log-line-number';
        lineNumber.textContent = log.lineNumber;

        lineDiv.appendChild(lineNumber);
        lineDiv.appendChild(document.createTextNode(log.raw));

        // Add title attribute for matched keywords
        if (log.matchedKeywords.length > 0) {
            lineDiv.title = `Matched: ${log.matchedKeywords.join(', ')}`;
        }

        logViewer.appendChild(lineDiv);
    });
}

/**
 * Render alerts to the UI
 * @param {Array} alerts - Array of alert objects
 */
function renderAlerts(alerts) {
    const alertsList = elements.alertsList;
    alertsList.innerHTML = '';

    if (alerts.length === 0) {
        alertsList.innerHTML = `
            <div class="no-alerts">
                <div class="no-alerts-icon">✅</div>
                <p>No security alerts detected</p>
            </div>
        `;
        return;
    }

    alerts.forEach((alert, index) => {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert-item ${alert.type}`;
        alertDiv.style.animationDelay = `${index * 0.05}s`;

        const icon = document.createElement('span');
        icon.className = 'alert-icon';
        icon.textContent = alert.type === 'critical' ? '🚨' : '⚠️';

        const content = document.createElement('div');
        content.className = 'alert-content';

        const title = document.createElement('div');
        title.className = 'alert-title';
        title.textContent = alert.title;

        const description = document.createElement('div');
        description.className = 'alert-description';
        description.textContent = alert.description;

        content.appendChild(title);
        content.appendChild(description);

        alertDiv.appendChild(icon);
        alertDiv.appendChild(content);

        alertsList.appendChild(alertDiv);
    });
}

/**
 * Render affected IPs to the UI
 * @param {Array} ips - Array of affected IP objects
 */
function renderIPs(ips) {
    const ipsList = elements.ipsList;
    ipsList.innerHTML = '';

    if (ips.length === 0) {
        ipsList.innerHTML = `
            <div class="no-alerts">
                <p>No suspicious IP addresses detected</p>
            </div>
        `;
        return;
    }

    ips.forEach((ipData, index) => {
        const ipTag = document.createElement('div');
        ipTag.className = 'ip-tag';
        ipTag.style.animationDelay = `${index * 0.05}s`;

        const ipText = document.createElement('span');
        ipText.textContent = ipData.ip;

        const count = document.createElement('span');
        count.className = 'ip-count';
        count.textContent = ipData.criticalCount + ipData.warningCount;
        count.title = `${ipData.criticalCount} critical, ${ipData.warningCount} warnings`;

        ipTag.appendChild(ipText);
        ipTag.appendChild(count);

        ipsList.appendChild(ipTag);
    });
}

/**
 * Update summary dashboard
 * @param {Object} summary - Summary statistics
 */
function updateSummary(summary) {
    animateNumber(elements.totalAlerts, summary.totalAlerts);
    animateNumber(elements.criticalAlerts, summary.critical);
    animateNumber(elements.warningAlerts, summary.warning);
    animateNumber(elements.affectedIPs, summary.affectedIPCount);
}

/**
 * Animate number counting
 * @param {HTMLElement} element - Element to update
 * @param {number} target - Target number
 */
function animateNumber(element, target) {
    const duration = 500;
    const start = parseInt(element.textContent) || 0;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Ease out quad
        const easeProgress = 1 - (1 - progress) * (1 - progress);
        const current = Math.round(start + (target - start) * easeProgress);
        
        element.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

/**
 * Main analysis function
 */
function analyzeLogs() {
    const logText = elements.logInput.value;

    if (!logText.trim()) {
        alert('Please enter some log data to analyze.');
        return;
    }

    // Add analyzing state
    elements.analyzeBtn.classList.add('analyzing');
    elements.analyzeBtn.disabled = true;

    // Use setTimeout to allow UI to update
    setTimeout(() => {
        // Parse logs
        const parsedLogs = parseLogs(logText);

        if (parsedLogs.length === 0) {
            alert('No valid log entries found.');
            elements.analyzeBtn.classList.remove('analyzing');
            elements.analyzeBtn.disabled = false;
            return;
        }

        // Detect patterns
        const results = detectPatterns(parsedLogs);
        analysisResults = results;

        // Update UI
        updateSummary(results.summary);
        renderAlerts(results.alerts);
        renderIPs(results.affectedIPs);
        highlightThreats(parsedLogs);

        // Show results sections
        elements.resultsSection.style.display = 'flex';
        elements.viewerSection.style.display = 'block';

        // Remove analyzing state
        elements.analyzeBtn.classList.remove('analyzing');
        elements.analyzeBtn.disabled = false;

        // Scroll to results
        elements.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 300);
}

/**
 * Load sample logs into the input
 */
function loadSampleLogs() {
    elements.logInput.value = SAMPLE_LOGS;
    elements.logInput.focus();
}

/**
 * Clear all inputs and results
 */
function clearAll() {
    elements.logInput.value = '';
    elements.resultsSection.style.display = 'none';
    elements.viewerSection.style.display = 'none';
    analysisResults = null;

    // Reset counters
    elements.totalAlerts.textContent = '0';
    elements.criticalAlerts.textContent = '0';
    elements.warningAlerts.textContent = '0';
    elements.affectedIPs.textContent = '0';

    elements.logInput.focus();
}

// ============================================
// Event Listeners
// ============================================

// Analyze button
elements.analyzeBtn.addEventListener('click', analyzeLogs);

// Sample logs button
elements.sampleBtn.addEventListener('click', loadSampleLogs);

// Clear button
elements.clearBtn.addEventListener('click', clearAll);

// Keyboard shortcut: Ctrl+Enter to analyze
elements.logInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        analyzeLogs();
    }
});

// Real-time analysis on input (debounced)
let analysisTimeout;
elements.logInput.addEventListener('input', () => {
    clearTimeout(analysisTimeout);
    analysisTimeout = setTimeout(() => {
        if (elements.logInput.value.trim().length > 50) {
            // Only auto-analyze if there's substantial content
            analyzeLogs();
        }
    }, 1000);
});

// ============================================
// Initialization
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('🛡️ ThreatLens Log Analyzer initialized');
    console.log('💡 Tip: Press Ctrl+Enter to analyze logs quickly');
});