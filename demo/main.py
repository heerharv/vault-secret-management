"""
Main configuration module for the Flask application with database integration
"""

import os
import logging
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase


# Load environment variables from .env file
env_path = Path(__file__).resolve().parents[1] / '.env'
load_dotenv(dotenv_path=env_path)

# Configure logging
log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models"""
    pass


# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Initialize Flask-Migrate
migrate = Migrate()


def create_app(test_config=None):
    """Create and configure the Flask application"""
    # Create the app
    app = Flask(__name__)
    
    if test_config is None:
        # Setup a secret key, required by sessions
        app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "vault-demo-secret-key"
        
        # Configure the database, using the DATABASE_URL environment variable
        app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "pool_recycle": 300,
            "pool_pre_ping": True,
        }
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        
        # Log configuration information
        logger.info(f"Starting application with {os.environ.get('FLASK_ENV', 'production')} configuration")
        logger.info(f"Using database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    else:
        # Load the test config if passed in
        app.config.update(test_config)
    
    # Initialize the app with the extensions
    db.init_app(app)
    migrate.init_app(app, db)
    
    with app.app_context():
        # Import the models to ensure they're registered
        import models  # noqa: F401
        
        try:
            # Create database tables
            db.create_all()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
        
        # Import and register blueprints/routes
        from routes import vault_api
        app.register_blueprint(vault_api)
        
    return app