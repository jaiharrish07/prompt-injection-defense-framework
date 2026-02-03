"""
Script to start the PromptGuard web server
"""
import subprocess
import sys
import webbrowser
import time

def start_server():
    """Start the Flask server"""
    print("Starting PromptGuard Server...")
    print("Access the web interface at: http://localhost:5000")
    print("Press Ctrl+C to stop the server\n")
    
    # Import and run the Flask app directly
    from app import app
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == "__main__":
    start_server()