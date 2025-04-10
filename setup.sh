#!/bin/bash
# Setup script for the Vault Demo project
# This script sets up the development environment and database for VS Code users

set -e
echo "Setting up Vault Demo development environment..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r demo/requirements.txt

# Set up database
if [ -z "$DATABASE_URL" ]; then
    echo "Creating a local PostgreSQL database..."
    # Check if PostgreSQL is running
    if ! pg_isready > /dev/null 2>&1; then
        echo "Error: PostgreSQL is not running. Please start PostgreSQL and try again."
        exit 1
    fi
    
    # Create database if it doesn't exist
    if ! psql -lqt | cut -d \| -f 1 | grep -qw vault_demo; then
        echo "Creating vault_demo database..."
        createdb vault_demo
    else
        echo "Database vault_demo already exists."
    fi
    
    # Set DATABASE_URL in .env
    if ! grep -q "DATABASE_URL=" .env 2>/dev/null; then
        echo "DATABASE_URL=postgresql://localhost:5432/vault_demo" >> .env
    fi
else
    echo "Using existing DATABASE_URL from environment."
fi

# Initialize migration repository if it doesn't exist
if [ ! -d "demo/migrations/versions" ]; then
    echo "Initializing Flask-Migrate..."
    cd demo
    export FLASK_APP=app.py
    flask db init
    cd ..
fi

# Generate migration script
echo "Generating database migration..."
cd demo
export FLASK_APP=app.py
flask db migrate -m "Initial migration"
flask db upgrade
cd ..

# Create mock Vault data
echo "Setting up mock Vault data..."
if ! grep -q "USE_MOCK_VAULT=true" .env 2>/dev/null; then
    echo "USE_MOCK_VAULT=true" >> .env
fi

echo "Setup complete! You can now run the application:"
echo "  - Start the application: cd demo && flask run"
echo "  - Or debug using VS Code Run and Debug panel"