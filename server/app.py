import uvicorn
# This points the robot to your REAL code inside soc_analyst_env
from soc_analyst_env.server.app import app as main_app

app = main_app

def main():
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    main()
    
    