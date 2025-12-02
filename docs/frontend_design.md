- ids_frontend(Frontend logic):
    - src: Sources files of all components composed of the frontend
        - app.jsx: Fetch data, listen to WebSocket updates, and renders dashboard layout(think of this
        as the main page that will display the frontend)

        - main.jsx: Renders the App component into root HTML element

        - styles.css: Dashboard styling

        - components:
            - alerts_list.jsx: scrollable list of recent alerts with details such as the detector name, soure ip, timestamp

            - icmp_chart.jsx: renders live updating line chart to show icmp packets per second alongside a baseline for anomoly comparison

            - arp_chart.jsx: renders live updating line chart to show possible arp packets(possible spoof) per second alongside a baseline for anomoly comparison

            - portscan_chart.jsx: renders live updating line chart to show syn packets(both tcp and udp that can indicate port scanning) per second alongside a baseline for anomoly comparison

            - ssh_chart.jsx: renders live updating line chart to show ssh attempts per second alongside a baseline for anomoly comparison

            - status_card.jsx: displays overall system heath, last update, and number of live alerts

            - EmailSettingsPanel.jsx: displays email parameter and to submit email for notifications

            - ThresholdPanel.jsx: Allows for threshold adjustments for the detectors 

        - services: 
            - websocket.js: Keeps persistent WebSocket connection to receive real time alert and stat updates from backend

            - api.js: Contains helper functions to fetch alerts and statistics via REST calls from FastAPI backend(one time fetch)

    - index.html: Main HTML file that hosts React app-- provides root container where dashboard is rendered

    - package.json: The packages needed
