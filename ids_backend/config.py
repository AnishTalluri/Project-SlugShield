<<<<<<< HEAD
import yaml
import os

# In the off chance config.yaml somehow fails to load, the backend will use this dictionary
=======
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
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
defaults = {
    'interface': None,
    'window_seconds': 10,
    'icmp_threshold_per_window': 100,
    'logging': {'alerts_log': 'alerts.log', 'level': 'INFO'},
}

<<<<<<< HEAD
# Load the config.yaml file, merge the default dictionary with config.yaml if there are any differencees
# Return object -> use dot notation
def load_config_file(path = 'config.yaml'):
    app_config = defaults.copy()
    if os.path.exists(path):
        with open(path, 'r') as f:
            user = yaml.safe_load(f) or {}
            for key, value in user.items():
                # This if statement is moreso to handle values that are dictionaries such as the logging key
=======
# ----------------------------
# YAML config loader
# ----------------------------
def load_config_file(path='config.yaml'):
    app_config = defaults.copy()

    if os.path.exists(path):
        with open(path, 'r') as f:
            user = yaml.safe_load(f) or {}

            for key, value in user.items():
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
                if isinstance(value, dict) and key in app_config:
                    app_config[key].update(value)
                else:
                    app_config[key] = value
<<<<<<< HEAD
    # Create class app_config, no inheritance, all keys from app_config dictionary as attributes
    return type('app_config', (), app_config)
=======

    # return a simple object with attributes
    return type('AppConfig', (), app_config)
>>>>>>> 0ac1ede (Upload full IDS backend with email notifications and detectors)
