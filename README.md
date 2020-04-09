## Manual Box JWT Authentication  
### System Requirements
[Python 3.6+](https://www.python.org/downloads/)  
[PIP package manager](https://pip.pypa.io/en/stable/installing/)  
[virtualenv](https://virtualenv.pypa.io/en/latest/) 
### Set up and Run
1. From the project root folder, create a Python 3.6+ virtual environment.  
`$ virtualenv --python=python3 env`
2. Activate the virtual environment.  
`$ source env/bin/activate`
3. Install the project dependencies.  
`$ pip install -r requirements.txt`
4. Add a Box Platform custom JWT app's keys to the projects root folder with a file name matching what's below.  
`jwt_auth.json`
5. Run the script and review the terminal logs to see an access token  
`python main.py do-box-jwt-auth`
