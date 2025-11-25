// Helper functions to fetch data from backend rest api
const base = 'http://127.0.0.1:8080'; // Update this if backend url ever changes

// Fetch recent alerts from backend
export async function fetch_alerts(limit = 100) {
    try {
        const response = await fetch(`${base}/api/alerts?limit=${limit}`);
        const data = await response.json();
        // Return data or [] if and only if field missing
        return data.alerts || [];
    } catch (error) {
        // Just in case of errors
        console.error('fetch_alerts error', error);
        return [];
    }
}

// Fetch icmp packet-rate statistics for charting
export async function fetch_icmp_stats(interval = 60) {
    try {
        const response = await fetch(`${base}/api/stats/icmp?interval=${interval}`);
        const data = await response.json();
        // Return data or [] if and only if field missing
        return data.stats || [];
    } catch (error) {
        // Once again, just in case of errors
        console.error('fetch_icmp_stats error', error);
        return [];
    }
}