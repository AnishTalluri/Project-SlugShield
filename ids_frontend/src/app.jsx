// Controls all dashboard logic and live updates
import React, { useState, useEffect, useCallback } from 'react';
import StatusCard from './components/status_card.jsx';
import AlertsList from './components/alerts_list.jsx';
import IcmpChart from './components/icmp_chart.jsx';
import { fetch_alerts, fetch_icmp_stats } from './services/api.js';
import { create_alert_socket } from './services/websocket.js';

export default function App() {
    const [alerts, set_alerts] = useState([]);
    const [stats, set_stats] = useState([]);
    const [baseline, set_baseline] = useState([]);
    const [status, set_status] = useState('Ok');
    const [last_checked, set_last_checked] = useState(null);

    // Helper function to add new alert
    const push_alert = useCallback((a) => {
        set_alerts(prev => {
            // Preventing duplicates
            if (prev.length > 0 && prev[0]?.id === a.id) return prev;
            // Append new alert 
            return [a, ...prev].slice(0, 200);
        });
        // Updates status from OK to Alert
        set_status('Alert');
        set_last_checked(new Date().toLocaleTimeString());
    }, []);

    // Helper function to add new stat
    const push_stat = useCallback((s) => {
        set_stats(prev => {
            // Utilize only the last 10 mins of data
            const next = [...prev, s].filter(p => Date.now()/1000 - p.timestamp <= 600);
            return next.slice(-600);
        });
        set_last_checked(new Date().toLocaleTimeString()); // Update last refresh timestamp

        // Calculate baseline for comparison by getting the rolling average 
        set_baseline(prev => {
            const all = [...stats.map(x=>x.value), s.value]; // Get previous packet rates
            const mean = all.length ? (all.reduce((a, b) => a + b, 0) / all.length) : s.value; 
            return [...prev, { timestamp: s.timestamp, value: mean }].slice(-600); // Keep only last 600 data points
        });
    }, [stats]);

    // Initial load
    useEffect(() => {
        (async () => {
            // Load last 100 alerts
            const a = await fetch_alerts(100);
            set_alerts(a);
            // Load last 60 seconds of icmp stats
            const s = await fetch_icmp_stats(60);
            // Just updating data, time, status 
            set_stats(s);
            set_last_checked(new Date().toLocaleTimeString());
            set_status(a.length ? 'Alert' : 'Ok');
        })();
    }, []);

    // Real time websocket updates
    useEffect(() => {
        const websocket = create_alert_socket((message) => {
            // Add a new alert
            if (message.type === 'alert' && message.payload) {
                push_alert(message.payload);
            }
            // Add new traffic data point
            else if (message.type === 'stat' && message.payload) {
                push_stat(message.payload);
            }
            // initial push of alerts from backend
            else if (message.type === 'init' && message.alerts) {
                set_alerts(message.alerts.concat(alerts).slice(0, 200));
                // If any alerts exist, then set status to alert
                if (message.alerts.length > 0) {
                    set_status('Alert');
                }
            }
            // Initial stats
            else if (message.type === 'init_stats' && message.stats) {
                set_stats(message.stats);
            }
        });
        return () => websocket.close();
    }, [push_alert, push_stat]);

    // Renders webpage layout -> UI part
    return (
        <div>
            <header>
                <h1>
                    IDS - Local Dashboard
                </h1>
            </header>

            <StatusCard status = {status} last_checked = {last_checked} active_alert = {alerts}/>
            <main>
                <section className = "left">
                    <IcmpChart stats = {stats} baseline = {baseline}/>
                </section>

                <aside className = "right">
                    <AlertsList alerts = {alerts}/>
                </aside>
            </main>

            <footer>
                <small>Backend: http://localhost:8080</small>
            </footer>
        </div>
    );
}