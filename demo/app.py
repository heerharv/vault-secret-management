#!/usr/bin/env python3
"""
Demo application launcher
"""

from main import create_app

# Create the Flask application with database configuration
app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)