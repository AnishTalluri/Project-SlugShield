// Renders live ICMP traffic chart
import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from 'recharts';

export default function IcmpChart({ stats = [], baseline = [] }) {
    // Filter stats for ICMP packets only
    const icmpStats = stats.filter(s => s.metric === "icmp_packets_per_second");

    // Map to chart points
    const points = icmpStats.map(s => ({
        time: new Date(s.timestamp * 1000).toLocaleTimeString(),
        value: s.value
    }));

    // Map baseline values (rolling average)
    const baselineMap = new Map(
        baseline.map(b => [new Date(b.timestamp * 1000).toLocaleTimeString(), b.value])
    );

    const data = points.map(p => ({
        ...p,
        baseline: baselineMap.get(p.time) ?? null
    }));

    return (
        <div className="chart-card">
            <h3>ICMP Packets / s</h3>
            <ResponsiveContainer width="100%" height={240}>
                <LineChart data={data}>
                    <CartesianGrid stroke="#f5f5f5" />
                    <XAxis dataKey="time" minTickGap={20} />
                    <YAxis />
                    <Tooltip />
                    <Line
                        type="monotone"
                        dataKey="value"
                        stroke="#8884d8"
                        strokeWidth={3}
                        dot={{ r: 4 }}
                        isAnimationActive={false}
                    />
                    <Line
                        type="monotone"
                        dataKey="baseline"
                        stroke="#82ca9d"
                        dot={false}
                        strokeDasharray="5 5"
                    />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}
