#!/usr/bin/env python3
"""
Demo application launcher for Vault integration showcase

This application demonstrates using HashiCorp Vault for secrets management
with a Flask application integrating PostgreSQL database and providing
a dashboard for managing secrets, SSH certificates, and AWS credentials.
"""

import os
import logging
from pathlib import Path

from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).resolve().parents[1] / '.env'
load_dotenv(dotenv_path=env_path)

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from main import create_app

# Create the Flask application with database configuration
app = create_app()

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'true').lower() in ('true', '1', 't')
    port = int(os.environ.get('PORT', 5000))
    
    logger.info(f"Starting application on port {port} with debug={debug_mode}")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)