"""
Main configuration module for the Flask application with database integration
"""

import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)

def create_app():
    """Create and configure the Flask application"""
    # create the app
    app = Flask(__name__)
    
    # setup a secret key, required by sessions
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "vault-demo-secret-key"
    
    # configure the database, using the DATABASE_URL environment variable
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    
    # initialize the app with the extension, flask-sqlalchemy >= 3.0.x
    db.init_app(app)
    
    with app.app_context():
        # Import the models to ensure they're registered
        import models  # noqa: F401
        
        # Create database tables
        db.create_all()
        
        # Import and register blueprints/routes
        from routes import vault_api
        app.register_blueprint(vault_api)
        
    return app