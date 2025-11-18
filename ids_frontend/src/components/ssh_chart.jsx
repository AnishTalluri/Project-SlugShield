// Renders live SSH attempts chart
import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from 'recharts';

export default function SshChart({ stats = [], baseline = [] }) {
    // Filter stats for SSH attempts only
    const sshStats = stats.filter(s => s.metric === "ssh_attempts_per_second");

    // Map to chart data
    const points = sshStats.map(s => ({
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
            <h3>SSH Attempts / s</h3>
            <ResponsiveContainer width="100%" height={240}>
                <LineChart data={data}>
                    <CartesianGrid stroke="#f5f5f5" />
                    <XAxis dataKey="time" minTickGap={20} />
                    <YAxis />
                    <Tooltip />
                    <Line type="monotone" dataKey="value" stroke="#ff7300" dot={true} strokeWidth={2} />
                    <Line type="monotone" dataKey="baseline" stroke="#82ca9d" dot={false} strokeDasharray="5 5" />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}
