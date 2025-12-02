// Show scrollable list of recent alerts with modern dark theme
import React from 'react';

// Helper function to determine alert severity class
function getAlertSeverity(alert) {
    // Check if message contains high numbers (indicating severity)
    const match = alert.message?.match(/(\d+)/);
    if (match) {
        const value = parseInt(match[1]);
        if (value > 50) return 'alert-item'; // High severity (red)
        if (value > 20) return 'alert-item warning'; // Medium severity (orange)
    }
    return 'alert-item info'; // Low severity (blue)
}

// Helper function to format detector name for display
function formatDetectorName(detector) {
    const nameMap = {
        'icmp_flood': 'ICMP Flood Detected',
        'ssh_bruteforce': 'SSH Brute Force',
        'arp_spoofing': 'ARP Spoofing',
        'port_scan': 'Port Scan Activity'
    };
    return nameMap[detector] || detector.replace(/_/g, ' ').toUpperCase();
}

// Helper function to render a single alert card
function AlertItem({ alert }) {
    const severityClass = getAlertSeverity(alert);
    const detectorName = formatDetectorName(alert.detector);

    return (
        <div className={severityClass}>
            <div className="alert-header">
                <div className="alert-type">{detectorName}</div>
                <div className="alert-time">
                    {new Date(alert.timestamp * 1000).toLocaleTimeString()}
                </div>
            </div>
            <div className="alert-details">
                {alert.src && (
                    <>
                        Source: <span className="alert-ip">{alert.src}</span>
                        {alert.message && <> • {alert.message}</>}
                    </>
                )}
                {!alert.src && alert.message && alert.message}
            </div>
        </div>
    );
}

// Component shown on webpage
export default function AlertsList({ alerts = [] }) {
    return (
        <div className="alerts-list">
            <div className="panel-header">
                <div className="panel-title">Active Alerts</div>
                {alerts.length > 0 && (
                    <div className="panel-badge">{alerts.length}</div>
                )}
            </div>
            {alerts.length === 0 ? (
                <div className="no-alerts">
                    ✓ No active alerts<br />
                    <span style={{ fontSize: '12px', color: '#666' }}>System is secure</span>
                </div>
            ) : (
                <div className="alerts-container">
                    {alerts.map((alert, index) => (
                        <AlertItem key={alert.id || `${alert.timestamp}-${index}`} alert={alert} />
                    ))}
                </div>
            )}
        </div>
    );
}