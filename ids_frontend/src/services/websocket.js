// Handles real time data updates through websocket connection
export function create_alert_socket(on_message) {
    const url = 'ws://127.0.0.1:8080/websocket/alerts';
    let websocket = new WebSocket(url); // create new websocket connection to the endpoint of the fastapi above

    // Connection success
    websocket.onopen = () => {
        console.log('websocket connected');
    };

    // Handle messages received from server
    websocket.onmessage = (event) => {
        try {
            // Parse the raw message string sent from backend
            const data = JSON.parse(event.data);
            // Call user callback with parsed message
            on_message(data)
        } catch (error) {
            // Error in parsing 
            console.error('websocket parsing error:', error);
        }
    };

    // When connection closes -> log connection closed and give reason-- also trying reconnection
    websocket.onclose = (event) => {
        console.log('websocket closed, reconnecting in 2 seconds', event.reason);
        setTimeout(() => create_alert_socket(on_message), 2000);
    };

    // Runtime errors during connection
    websocket.onerror = (error) => {
        console.error('websocket error', error);
        websocket.close();
    };

    return websocket;
}