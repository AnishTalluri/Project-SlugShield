# ids_backend/config.py

import yaml
import os

# ----------------------------
# Default static thresholds
# ----------------------------
thresholds = {
    "ssh": 10,
    "icmp": 20,
    "arp": 5
}

# ----------------------------
# Default config for app_config loader
# ----------------------------
defaults = {
    'interface': None,
    'window_seconds': 10,
    'icmp_threshold_per_window': 100,
    'arp_mac_change_threshold': 3,
    'logging': {'alerts_log': 'alerts.log', 'level': 'INFO'},
}

# ----------------------------
# YAML config loader
# ----------------------------
def load_config_file(path='config.yaml'):
    app_config = defaults.copy()

    if os.path.exists(path):
        with open(path, 'r') as f:
            user = yaml.safe_load(f) or {}

            for key, value in user.items():
                if isinstance(value, dict) and key in app_config:
                    app_config[key].update(value)
                else:
                    app_config[key] = value

    # return a simple object with attributes
    return type('AppConfig', (), app_config)
