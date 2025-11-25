// Main ids dashboard component-- controls all dashboard logic and live updates
import React, { useState, useEffect, useCallback } from 'react';
import StatusCard from './components/status_card.jsx';
import AlertsList from './components/alerts_list.jsx';
import IcmpChart from './components/icmp_chart.jsx';
import SshChart from './components/ssh_chart.jsx';
import ThresholdPanel from "./components/ThresholdPanel.jsx";
import EmailSettingsPanel from "./components/EmailSettingsPanel.jsx";
import { fetch_alerts, fetch_icmp_stats } from './services/api.js';
import { create_alert_socket } from './services/websocket.js';

export default function App() {
    const [alerts, set_alerts] = useState([]);
    const [icmpStats, setIcmpStats] = useState([]);
    const [icmpBaseline, setIcmpBaseline] = useState([]);
    const [sshStats, setSshStats] = useState([]);
    const [sshBaseline, setSshBaseline] = useState([]);
    const [status, set_status] = useState('Ok');
    const [last_checked, set_last_checked] = useState(null);

    // Helper: Add new alert 
    const push_alert = useCallback((a) => {
        set_alerts(prev => {
            if (prev.length > 0 && prev[0]?.id === a.id) return prev; // prevent duplicates
            return [a, ...prev].slice(0, 200);
        });
        set_status('Alert');
        set_last_checked(new Date().toLocaleTimeString());
    }, []);

    // Helper: Add new stat (ICMP or SSH)
    const push_stat = useCallback((stat) => {
        const now = Date.now() / 1000;

        const update_stats = (prevStats, prevBaseline, metricKey) => {
            // Updates detector stats with rolling window of detector stats for chart, only keeping last 10 min of stats for specific metric
            const filtered = [...prevStats, stat].filter(p => p.metric === metricKey && (Date.now() / 1000 - p.timestamp <= 600));
            const values = filtered.map(x => x.value);
            // Get average by summing all number and divide by # of elements 
            const mean = values.length ? values.reduce((a, b) => a + b, 0) / values.length : stat.value;
            const updatedBaseline = [...prevBaseline, { timestamp: stat.timestamp, value: mean }].slice(-600);
            // Add to baseline array-- keep last 600 baseline points
            return [filtered.slice(-600), updatedBaseline];
        };

        if (stat.metric === 'icmp_packets_per_second') {
            const [updated_stats, updated_baseline] = update_stats(icmpStats, icmpBaseline, stat.metric)
            setIcmpStats(updated_stats);
            setIcmpBaseline(updated_baseline);
        } else if (stat.metric === 'ssh_attempts_per_second') {
            const [updated_stats, updated_baseline] = update_stats(sshStats, sshBaseline, stat.metric)
            setSshStats(updated_stats);
            setSshBaseline(updated_baseline);
        }

        set_last_checked(new Date().toLocaleTimeString());
    }, [icmpStats, icmpBaseline, sshStats, sshBaseline]);

    // === Initial load (alerts + stats) ===
    useEffect(() => {
        (async () => {
            const initial_alerts = await fetch_alerts(100);
            set_alerts(initial_alerts);

            const initial_icmp_stats = await fetch_icmp_stats(60);
            setIcmpStats(initial_icmp_stats);

            set_last_checked(new Date().toLocaleTimeString());
            set_status(initial_alerts.length ? 'Alert' : 'Ok');
        })();
    }, []);

    // === Real-time websocket updates ===
    useEffect(() => {
        const websocket = create_alert_socket((message) => {
            if (message.type === 'alert' && message.payload) {
                push_alert(message.payload);
            } else if (message.type === 'stat' && message.payload) {
                push_stat(message.payload);
            } else if (message.type === 'init' && message.alerts) {
                set_alerts(message.alerts.concat(alerts).slice(0, 200));
                if (message.alerts.length > 0) set_status('Alert');
            } else if (message.type === 'init_stats' && message.stats) {
                const icmp = message.stats.filter(s => s.metric === 'icmp_packets_per_second');
                const ssh = message.stats.filter(s => s.metric === 'ssh_attempts_per_second');
                setIcmpStats(icmp);
                setSshStats(ssh);
            }
        });

        return () => websocket.close();
    }, [push_alert, push_stat]);

    // Auto-refresh both ICMP + SSH stats every 5s 
    useEffect(() => {
        const interval = setInterval(async () => {
            try {
                // Simulate test traffic on backend
                await fetch("http://127.0.0.1:8080/api/test/stats", { method: "POST" });

                // Fetch latest ICMP stats
                const resIcmp = await fetch("http://127.0.0.1:8080/api/stats/icmp");
                const dataIcmp = await resIcmp.json();
                dataIcmp.stats.forEach(stat => push_stat(stat));

                // Fetch latest SSH stats
                const resSsh = await fetch("http://127.0.0.1:8080/api/stats/ssh");
                if (resSsh.ok) {
                    const dataSsh = await resSsh.json();
                    dataSsh.stats.forEach(stat => push_stat(stat));
                }
            } catch (err) {
                console.error("Auto-refresh error:", err);
            }
        }, 5000);

        return () => clearInterval(interval);
    }, [push_stat]);

    // === Render UI ===
    return (
        <div>
            <header>
                <h1>IDS - Local Dashboard</h1>
            </header>

            <StatusCard status={status} last_checked={last_checked} active_alert={alerts} />

            <main>
                <section className="left">
                    <IcmpChart stats={icmpStats} baseline={icmpBaseline} />
                    <SshChart stats={sshStats} baseline={sshBaseline} />
                </section>

                <aside className="right">
                    {/* Settings */}
                    <ThresholdPanel />
                    <EmailSettingsPanel />

                    {/* Alerts */}
                    <AlertsList alerts={alerts} />
                </aside>
            </main>

            <footer>
                <small>Backend: http://localhost:8080</small>
            </footer>
        </div>
    );
}
