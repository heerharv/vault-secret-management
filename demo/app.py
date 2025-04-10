#!/usr/bin/env python3
"""
Demo application showing Vault integration with a web application
"""

import os
import hvac
import requests
import logging
from flask import Flask, render_template, jsonify
from functools import wraps

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Vault configuration
VAULT_ADDR = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
VAULT_TOKEN = os.environ.get('VAULT_TOKEN')

# In-memory cache for secrets (in production, use a secure cache like Redis)
# This is just for demonstration purposes
secrets_cache = {}

def vault_client():
    """Create and return a Vault client"""
    if not VAULT_TOKEN:
        logger.error("VAULT_TOKEN environment variable not set!")
        return None
    
    try:
        client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
        if not client.is_authenticated():
            logger.error("Vault client failed to authenticate!")
            return None
        return client
    except Exception as e:
        logger.error(f"Error creating Vault client: {e}")
        return None

def requires_vault(f):
    """Decorator to ensure Vault is available"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client = vault_client()
        if not client:
            return jsonify({
                'error': 'Vault connection not available',
                'message': 'Please check Vault server and token'
            }), 503
        return f(client, *args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Main page"""
    vault_status = "Connected" if vault_client() else "Disconnected"
    return render_template('index.html', vault_status=vault_status)

@app.route('/api/status')
def status():
    """Get Vault status"""
    client = vault_client()
    if not client:
        return jsonify({
            'status': 'error',
            'message': 'Vault connection not available'
        }), 503
    
    try:
        status = client.sys.read_health_status(method='GET')
        return jsonify({
            'status': 'ok',
            'vault_status': status
        })
    except Exception as e:
        logger.error(f"Error getting Vault status: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/secrets/db')
@requires_vault
def get_db_secrets(client):
    """Get database secrets from Vault"""
    try:
        # Check cache first
        if 'db' in secrets_cache:
            return jsonify({
                'status': 'ok',
                'data': secrets_cache['db'],
                'source': 'cache'
            })
        
        # Get from Vault
        secret = client.secrets.kv.v2.read_secret_version(
            path='application/database',
            mount_point='secret'
        )
        
        data = secret['data']['data']
        
        # Mask sensitive information for display
        masked_data = {
            'username': data['username'],
            'password': '********',  # Mask password
            'retrieved_at': secret['data']['metadata']['created_time']
        }
        
        # Save to cache
        secrets_cache['db'] = masked_data
        
        return jsonify({
            'status': 'ok',
            'data': masked_data,
            'source': 'vault'
        })
    except Exception as e:
        logger.error(f"Error retrieving database secrets: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/secrets/api')
@requires_vault
def get_api_secrets(client):
    """Get API secrets from Vault"""
    try:
        # Check cache first
        if 'api' in secrets_cache:
            return jsonify({
                'status': 'ok',
                'data': secrets_cache['api'],
                'source': 'cache'
            })
        
        # Get from Vault
        secret = client.secrets.kv.v2.read_secret_version(
            path='application/api',
            mount_point='secret'
        )
        
        data = secret['data']['data']
        
        # Mask sensitive information for display
        masked_data = {
            'api_key': data['api_key'][:4] + '********',  # Mask API key
            'retrieved_at': secret['data']['metadata']['created_time']
        }
        
        # Save to cache
        secrets_cache['api'] = masked_data
        
        return jsonify({
            'status': 'ok',
            'data': masked_data,
            'source': 'vault'
        })
    except Exception as e:
        logger.error(f"Error retrieving API secrets: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/ssh/generate')
@requires_vault
def generate_ssh_demo(client):
    """Demonstrate SSH certificate generation"""
    try:
        # This is just a demonstration - in a real app, you would:
        # 1. Get the user's public key
        # 2. Sign it with Vault
        # 3. Return the signed certificate
        
        # Here we'll just show the SSH roles available
        response = requests.get(
            f"{VAULT_ADDR}/v1/ssh/roles",
            headers={"X-Vault-Token": VAULT_TOKEN}
        )
        response.raise_for_status()
        
        return jsonify({
            'status': 'ok',
            'message': 'SSH certificate generation demo',
            'available_roles': response.json().get('data', {}).get('keys', []),
            'instructions': [
                'In a real application, you would:',
                '1. Upload your SSH public key',
                '2. Have it signed by Vault',
                '3. Download the signed certificate',
                '4. Use it for SSH authentication'
            ]
        })
    except Exception as e:
        logger.error(f"Error in SSH certificate demo: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/aws/roles')
@requires_vault
def list_aws_roles(client):
    """List available AWS roles"""
    try:
        response = requests.get(
            f"{VAULT_ADDR}/v1/aws/roles",
            headers={"X-Vault-Token": VAULT_TOKEN}
        )
        response.raise_for_status()
        
        return jsonify({
            'status': 'ok',
            'available_roles': response.json().get('data', {}).get('keys', []),
            'instructions': [
                'To generate AWS credentials:',
                '1. Use the Ansible playbook: aws-credential-rotation.yml',
                '2. Or the Python script: rotate-aws-creds.py'
            ]
        })
    except Exception as e:
        logger.error(f"Error listing AWS roles: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/auth/methods')
@requires_vault
def list_auth_methods(client):
    """List enabled auth methods"""
    try:
        auth_methods = client.sys.list_auth_methods()
        
        # Filter out details for simpler display
        methods = {}
        for path, details in auth_methods['data'].items():
            methods[path] = {
                'type': details['type'],
                'description': details['description']
            }
        
        return jsonify({
            'status': 'ok',
            'auth_methods': methods
        })
    except Exception as e:
        logger.error(f"Error listing auth methods: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/clear-cache')
def clear_cache():
    """Clear the secrets cache"""
    global secrets_cache
    secrets_cache = {}
    return jsonify({
        'status': 'ok',
        'message': 'Cache cleared'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
