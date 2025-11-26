// Controls all dashboard logic and live updates
import React, { useState, useEffect, useCallback } from 'react';
import StatusCard from './components/status_card.jsx';
import AlertsList from './components/alerts_list.jsx';
import IcmpChart from './components/icmp_chart.jsx';
import SshChart from './components/ssh_chart.jsx';
import ArpChart from './components/arp_chart.jsx';
import PortscanChart from './components/portscan_chart.jsx';
import ThresholdPanel from "./components/ThresholdPanel.jsx";
import EmailSettingsPanel from "./components/EmailSettingsPanel.jsx";
import { fetch_alerts, fetch_icmp_stats, create_alert_socket } from './services/api.js';

export default function App() {
    const [alerts, set_alerts] = useState([]);
    const [icmpStats, setIcmpStats] = useState([]);
    const [icmpBaseline, setIcmpBaseline] = useState([]);
    const [sshStats, setSshStats] = useState([]);
    const [sshBaseline, setSshBaseline] = useState([]);
    const [arpStats, setArpStats] = useState([]);
    const [arpBaseline, setArpBaseline] = useState([]);
    const [portscanStats, setPortscanStats] = useState([]);
    const [portscanBaseline, setPortscanBaseline] = useState([]);
    const [status, set_status] = useState('Ok');
    const [last_checked, set_last_checked] = useState(null);

    // === Helper: Add new alert ===
    const push_alert = useCallback((a) => {
        set_alerts(prev => {
            if (prev.length > 0 && prev[0]?.id === a.id) return prev;
            return [a, ...prev].slice(0, 200);
        });
    }, []);

    // === Helper: Add new stat (ICMP or SSH) ===
    const push_stat = useCallback((s) => {
        const now = Date.now() / 1000;

        if (s.metric === 'icmp_packets_per_second') {
            setIcmpStats(prev => {
                const next = [...prev, s].filter(p => now - p.timestamp <= 600);
                return next.slice(-600);
            });
            setIcmpBaseline(prev => {
                const all = [...icmpStats.map(x => x.value), s.value];
                const mean = all.length ? all.reduce((a, b) => a + b, 0) / all.length : s.value;
                return [...prev, { timestamp: s.timestamp, value: mean }].slice(-600);
            });
        } else if (s.metric === 'ssh_attempts_per_second') {
            setSshStats(prev => {
                const next = [...prev, s].filter(p => now - p.timestamp <= 600);
                return next.slice(-600);
            });
            setSshBaseline(prev => {
                const all = [...sshStats.map(x => x.value), s.value];
                const mean = all.length ? all.reduce((a, b) => a + b, 0) / all.length : s.value;
                return [...prev, { timestamp: s.timestamp, value: mean }].slice(-600);
            });
        } else if (s.metric === 'arp_spoofing_attempts_per_second') {
            setArpStats(prev => {
                const next = [...prev, s].filter(p => now - p.timestamp <= 600);
                return next.slice(-600);
            });
            setArpBaseline(prev => {
                const all = [...arpStats.map(x => x.value), s.value];
                const mean = all.length ? all.reduce((a, b) => a + b, 0) / all.length : s.value;
                return [...prev, { timestamp: s.timestamp, value: mean }].slice(-600);
            });
        } else if (s.metric === 'portscan_attempts_per_second') {
            setPortscanStats(prev => {
                const next = [...prev, s].filter(p => now - p.timestamp <= 600);
                return next.slice(-600);
            });
            setPortscanBaseline(prev => {
                const all = [...portscanStats.map(x => x.value), s.value];
                const mean = all.length ? all.reduce((a, b) => a + b, 0) / all.length : s.value;
                return [...prev, { timestamp: s.timestamp, value: mean }].slice(-600);
            });
        }

        set_last_checked(new Date().toLocaleTimeString());
    }, [icmpStats, sshStats, arpStats, portscanStats]);

    // === Initial load (alerts + stats) ===
    useEffect(() => {
        (async () => {
            const a = await fetch_alerts(100);
            set_alerts(a);

            const s = await fetch_icmp_stats(60);
            setIcmpStats(s);
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
                const arp = message.stats.filter(s => s.metric === 'arp_spoofing_attempts_per_second');
                const portscan = message.stats.filter(s => s.metric === 'portscan_attempts_per_second');
                setIcmpStats(icmp);
                setSshStats(ssh);
                setArpStats(arp);
                setPortscanStats(portscan);
            }
        });

        return () => websocket.close();
    }, [push_alert, push_stat, alerts]);

    // === Auto-refresh ICMP + SSH + ARP stats every 5s ===
    useEffect(() => {
        const fetchStats = async () => {
            try {
                let hasNewData = false;

                // Fetch latest ICMP stats
                const resIcmp = await fetch("http://127.0.0.1:8080/api/stats/icmp");
                const dataIcmp = await resIcmp.json();
                if (dataIcmp.stats && dataIcmp.stats.length > 0) {
                    dataIcmp.stats.forEach(stat => push_stat(stat));
                    hasNewData = true;
                }

                // Fetch latest SSH stats
                const resSsh = await fetch("http://127.0.0.1:8080/api/stats/ssh");
                if (resSsh.ok) {
                    const dataSsh = await resSsh.json();
                    if (dataSsh.stats && dataSsh.stats.length > 0) {
                        dataSsh.stats.forEach(stat => push_stat(stat));
                        hasNewData = true;
                    }
                }

                // Fetch latest ARP stats
                const resArp = await fetch("http://127.0.0.1:8080/api/stats/arp");
                if (resArp.ok) {
                    const dataArp = await resArp.json();
                    if (dataArp.stats && dataArp.stats.length > 0) {
                        dataArp.stats.forEach(stat => push_stat(stat));
                        hasNewData = true;
                    }
                }

                // Fetch latest Port Scan stats
                const resPortscan = await fetch("http://127.0.0.1:8080/api/stats/portscan");
                if (resPortscan.ok) {
                    const dataPortscan = await resPortscan.json();
                    if (dataPortscan.stats && dataPortscan.stats.length > 0) {
                        dataPortscan.stats.forEach(stat => push_stat(stat));
                        hasNewData = true;
                    }
                }

                // Update timestamp if we got new data OR if it's the initial load (last_checked is null)
                if (hasNewData || last_checked === null) {
                    set_last_checked(new Date().toLocaleTimeString());
                }
            } catch (err) {
                console.error("Auto-refresh error:", err);
            }
        };

        // Run immediately on mount
        fetchStats();

        // Then run every 5 seconds
        const interval = setInterval(fetchStats, 5000);

        return () => clearInterval(interval);
    }, [push_stat, last_checked]);

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
                    {console.log('ARP Stats:', arpStats)}
                    <ArpChart stats={arpStats} baseline={arpBaseline} />
                    <PortscanChart stats={portscanStats} baseline={portscanBaseline} />
                </section>

                <aside className="right">
                    {/* Settings */}
                    <ThresholdPanel />
                    <EmailSettingsPanel />

                    {/* Alerts */}
                    <AlertsList alerts={alerts} />
                </aside>
            </main>
        </div>
    );
}
