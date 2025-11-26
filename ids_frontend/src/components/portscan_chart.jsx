// Renders live port scan attempts chart
import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from 'recharts';

export default function PortscanChart({ stats = [], baseline = [] }) {
    // Filter stats for port scan attempts only
    const portscanStats = stats.filter(s => s.metric === "portscan_attempts_per_second");

    // Map to chart data
    const points = portscanStats.map(s => ({
        time: new Date(s.timestamp * 1000).toLocaleTimeString(),
        value: s.value
    }));

    // Map baselines (rolling averages)
    const baselineMap = new Map(
        baseline.map(b => [new Date(b.timestamp * 1000).toLocaleTimeString(), b.value])
    );

    const data = points.map(p => ({
        ...p,
        baseline: baselineMap.get(p.time) ?? null
    }));

    return (
        <div className="chart-card">
            <h3>Port Scan Attempts / s</h3>
            <ResponsiveContainer width="100%" height={240}>
                <LineChart data={data}>
                    <CartesianGrid stroke="#f5f5f5" />
                    <XAxis dataKey="time" minTickGap={20} />
                    <YAxis />
                    <Tooltip />
                    <Line type="monotone" dataKey="value" stroke="#6f42c1" strokeWidth={3} dot={{ r: 4 }} isAnimationActive={false} />
                    <Line type="monotone" dataKey="baseline" stroke="#82ca9d" dot={false} strokeDasharray="5 5" />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}
