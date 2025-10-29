// Helper functions to fetch data from backend rest api
const base = 'http://127.0.0.1:8080'; // Update this if backend ever updates

// Fetch recent alerts from backend
export async function fetch_alerts(limit = 100) {
    try {
        const response = await fetch(`${base}/api/alerts?limit=${limit}`);
        const json_response = await response.json();
        // Return json response or [] if and only if field missing
        return json_response.alerts || [];
    } catch (e) {
        // Just in case of errors
        console.error('fetch_alerts error', e);
        return [];
    }
}

// Fetch icmp packet-rate statistics for charting
export async function fetch_icmp_stats(interval = 60) {
    try {
        const response = await fetch(`${base}/api/stats/icmp?interval=${interval}`);
        const json_response = await response.json();
        // Return json response or [] if and only if field missing
        return json_response.stats || [];
    } catch (e) {
        // Once again, just in case of errors
        console.error('fetch_icmp_stats error', e);
        return [];
    }
}