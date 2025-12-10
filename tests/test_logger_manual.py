import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from supabash.logger import setup_logger, LOG_FILE

def test_logging():
    print(f"Setting up logger...")
    logger = setup_logger("test_logger")
    
    logger.debug("This is a debug message.")
    logger.info("This is an info message.")
    logger.warning("This is a warning message.")
    
    print(f"Log file expected at: {LOG_FILE}")
    
    if os.path.exists(LOG_FILE):
        print("Log file successfully created.")
        with open(LOG_FILE, 'r') as f:
            content = f.read()
            print("Log content preview:")
            print(content)
            if "This is a debug message." in content:
                print("SUCCESS: Debug message found in log.")
            else:
                print("FAILURE: Debug message NOT found in log.")
    else:
        print("FAILURE: Log file was not created.")

if __name__ == "__main__":
    test_logging()
