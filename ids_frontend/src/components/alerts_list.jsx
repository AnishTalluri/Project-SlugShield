// Show scrollable list of recent alerts
import React from 'react';

// Helper funtion to render a single alert card or row
function AlertItem({alert}) {
    return (
        <div className = "alert-item">
            <div className = "alert-header">
                <strong> {alert.detector}</strong>
                <span className = "time"> {new Date(alert.timestamp * 1000).toLocaleTimeString()}</span>
            </div>
            {/* Display single alert card here */}
            <div className = "alert-message"> {alert.message}</div>
            <div className = "alert-meta"> 
                {alert.src && <span>src: {alert.src}</span>}
                {alert.count !== undefined && <span>count: {alert.count}</span>}
            </div>
        </div>
    );
} 

// Component shown on webpage
export default function AlertsList({ alerts = []}) {
    return (
        <div className = "alerts-list">
            <h3>Recent Alerts</h3>
            {/* Initial display */}
            {alerts.length === 0 && <div className = "no-alerts"> No alerts</div>}

            {/* Displays all alert cards*/}
            <div className = "alerts-scroll">
                {alerts.map((alert) => <AlertItem key={alert.id || alert.timestamp} alert={alert} />)}
            </div>
        </div>
    );
}