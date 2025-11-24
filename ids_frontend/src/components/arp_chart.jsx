// Renders live ARP spoofing attempts chart
import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from 'recharts';

export default function ArpChart({ stats = [], baseline = [] }) {
    console.log('ArpChart received stats:', stats);
    console.log('ArpChart received baseline:', baseline);
    
    // Filter stats for ARP spoofing attempts only
    const arpStats = stats.filter(s => s.metric === "arp_spoofing_attempts_per_second");
    console.log('Filtered arpStats:', arpStats);

    // Map to chart data
    const points = arpStats.map(s => ({
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
            <h3>ARP Spoofing Attempts / s</h3>
            <ResponsiveContainer width="100%" height={240}>
                <LineChart data={data}>
                    <CartesianGrid stroke="#f5f5f5" />
                    <XAxis dataKey="time" minTickGap={20} />
                    <YAxis />
                    <Tooltip />
                    <Line type="monotone" dataKey="value" stroke="#dc3545" strokeWidth={3} dot={{ r: 4 }} isAnimationActive={false} />
                    <Line type="monotone" dataKey="baseline" stroke="#82ca9d" dot={false} strokeDasharray="5 5" />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}
