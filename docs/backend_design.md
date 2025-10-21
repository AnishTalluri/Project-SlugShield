- First thing is first, make sure you:
    - Are in the directory for this project 
    - Create an environment for testing: python3 -m venv venv
    - Activate environment: source venv/bin/activate(Please make sure to not push venv onto github-- no need to)
    - Download the packages needed for backend: pip install -r requirements.txt
        - Side Note: Some of these packages require the latest python update to run

- Backend logic:
    - run_backend.py: run the actual backend of the project 
    - ids_backend: The directory where all the backend logic will be stored: parsing, detecting, etc.
        - config.py: Loader and manager of configuration for project-- reads config.yaml and merge with defaults

- config.yaml: user-editable configuration-- you change threshold values and such here 