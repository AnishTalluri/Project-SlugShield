import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from 'recharts';

function convert_unix_timestamp_to_local_time_string(timestamp) {
    if (!timestamp) {
        return "Unknown";
    }
    return new Date(timestamp * 1000).toLocaleTimeString();
}

export default function IcmpChart({ stats = [], baseline = [] }) {
    // Filter stats for ICMP metrics only
    const icmpStats = stats.filter(s => s.metric === "icmp_packets_per_second");

    // Pre-format all timestamps one time before polluting to chart
    const points_list = icmpStats.map(s => ({
        time: convert_unix_timestamp_to_local_time_string(s.timestamp),
        value: s.value
    }));

    // Convert baseline list into a timestamp lookup chart -> baseline is calculated in app.jsx
    // This is moreso to quickly check if there is a baseline value for the exact timestamp
    const baselineMap = new Map(
        baseline.map(b => [
            convert_unix_timestamp_to_local_time_string(b.timestamp),
            b.value
        ])
    );

    // Merge ICMP points and baseline value into a single chart
    const data = points_list.map(p => ({
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
                        dot={true}
                        strokeWidth={2}
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
