- First thing is first, make sure you:
    - Are in the directory for this project 
    - Create an environment for testing: python3 -m venv venv
    - Activate environment: source venv/bin/activate(Please make sure to not push venv onto github-- no need to)
    - Download the packages needed for backend: pip install -r requirements.txt
        - Side Note: Some of these packages require the latest python update to run

- config.yaml: user-editable configuration-- you change threshold values and such here 
- run_backend.py: run the actual backend of the project
- tools
    - simulate_icmp_flood.py: sends a range of icmp packets to the detector
- requirements.txt
    - scapy: packet capture and network traffic analysis
    - fastapi: web api backend framework -> exposes data to frontend
    - uvicorn[standard]: runs the FastAPI backend, [standard] is for performance extra
    - python-dotenv: stores confirguration values in an environment file
    - pytest: for automated and integration testing
    - PyYAML: reading structured .yaml configs

- run_backend.py: entry point for IDS backend as well as starting FastAPI server and network packet detector within same event loop-- ensures real time updates flow to frontend via shared broadcaster

- How to start application:
    - Make sure you are in an environment first and have installed requirements.txt
    - Go into Project_Slugshild directory and run sudo -E venv/bin/python3 run_backend.py
    - Then go into ids_frontend directory and run npm run dev (run npm install first if you never ran it before)
    - Testing for icmp flood:
        - Set interface in config.yaml to lo0 just so you can test this on same machine
            - On different terminal run sudo -E venv/bin/python3 tools/simulate_icmp_flood.py 127.0.0.1 1000
                - 127.0.0.1 represents lo0 ip address
                - 1000 amount of packets you want to test 