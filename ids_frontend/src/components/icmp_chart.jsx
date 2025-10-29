// Renders live icmp traffic chart
import React from 'react';

// For charting
import {LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer} from 'recharts';

export default function IcmpChart ({stats = [], baseline = []}) {
    // Merge to chart points and attach baseline to points if possible
    const points = stats.map(s => ({time: new Date(s.timestamp * 1000).toLocaleTimeString(), value: s.value}));
    const baselineMap = new Map(baseline.map(b => [new Date(b.timestamp * 1000).toLocaleTimeString(), b.value]));
    const data = points.map(p => ({ ...p, baseline: baselineMap.get(p.time) ?? null}));

    return (
        <div className = "chart-card">
            <h3>ICMP Packets / s</h3>
            <ResponsiveContainer width = "100%" height = {240}>
                <LineChart data = {data}>
                    <CartesianGrid stroke = "#f5f5f5" />
                    <XAxis dataKey = "time" minTickGap = {20} />
                    <YAxis />
                    <Tooltip />
                    <Line type = "monotone" dataKey = "value" stroke = "#8884d8" dot = {false} strokeWidth = {2} />
                    <Line type = "monotone" dataKey = "baseline" stroke = "#82ca9d" dot = {false} strokeDasharray = "5 5" />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}