import json
import time

class alert_manager:
    def __init__(self, app_config):
        # Grab alerts_log from config.yaml-- if doesn't exist for some reason, default to alerts.log
        self.log_file = app_config.logging.get('alerts_log', 'alerts.log')

    # Write to alerts.log if anything is detected 
    def alert(self, payload: dict):
        payload = payload.copy() # To avoid any conflicts
        payload['timestamp'] = time.time()
        try:
            line = json.dumps(payload) # Convert to string in json formatted 
            print(f'[ALERT] {payload.get("message")}') # This is moreso for debugging but print the alert
            
            # Write to the log file
            with open(self.log_file, 'a') as f:
                f.write(line + '\n')
        except Exception as e:
            print(f'Failed to write alert: {e}')