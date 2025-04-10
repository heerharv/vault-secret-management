"""
Routes for the Vault demo application with database integration
"""

import os
import logging
import hvac
import requests
from datetime import datetime
from flask import Blueprint, jsonify, render_template, request, current_app
from models import db, Secret, AccessLog, SecretType, SecretAction, VaultRole
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create blueprint
vault_api = Blueprint('vault_api', __name__)

# Vault configuration
VAULT_ADDR = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
VAULT_TOKEN = os.environ.get('VAULT_TOKEN')

# In-memory cache for secrets (in production, use a secure cache like Redis)
# This is just for demonstration purposes
secrets_cache = {}

def vault_client():
    """Create and return a Vault client"""
    # Check if we should use the mock client (for demonstration)
    use_mock = os.environ.get('USE_MOCK_VAULT', 'true').lower() == 'true'
    
    if use_mock:
        # Import here to avoid circular imports
        from mock_vault import MockVaultClient
        logger.info("Using mock Vault client for demonstration")
        os.environ.setdefault('MOCK_VAULT_TOKEN', 'mock-token')
        return MockVaultClient(url=VAULT_ADDR, token='mock-token')
    
    # Use real Vault client
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

def log_access(secret_id, action, success=True):
    """Log access to secrets in the database"""
    try:
        log = AccessLog(
            secret_id=secret_id,
            action=action,
            client_ip=request.remote_addr,
            user_agent=request.user_agent.string,
            success=success
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error logging access: {e}")
        db.session.rollback()

@vault_api.route('/')
def index():
    """Main page - dashboard"""
    vault_status = "Connected" if vault_client() else "Disconnected"
    vault_addr = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
    
    # Get count of secrets by type
    secret_counts = {}
    try:
        for secret_type in SecretType:
            count = Secret.query.filter_by(type=secret_type).count()
            secret_counts[secret_type.value] = count
    except Exception as e:
        logger.error(f"Error getting secret counts: {e}")
        secret_counts = {}
    
    # Get recent access logs
    recent_logs = []
    try:
        logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(5).all()
        for log in logs:
            secret = Secret.query.get(log.secret_id)
            if secret:
                recent_logs.append({
                    'secret_name': secret.name,
                    'action': log.action.value,
                    'timestamp': log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'success': log.success
                })
    except Exception as e:
        logger.error(f"Error getting recent logs: {e}")
    
    # Get stats for dashboard
    total_secrets = Secret.query.count()
    total_roles = VaultRole.query.count()
    access_logs_count = AccessLog.query.count()
    ssh_certs_issued = AccessLog.query.join(Secret).filter(
        Secret.type == SecretType.SSH,
        AccessLog.action == SecretAction.READ,
        AccessLog.success == True
    ).count()
    
    return render_template('dashboard.html', 
                          active_page='dashboard',
                          vault_status=vault_status,
                          vault_addr=vault_addr,
                          secret_counts=secret_counts,
                          recent_logs=recent_logs,
                          total_secrets=total_secrets,
                          total_roles=total_roles,
                          access_logs_count=access_logs_count,
                          ssh_certs_issued=ssh_certs_issued)

@vault_api.route('/api/status')
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

@vault_api.route('/api/secrets/db')
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
        
        # Record in database
        try:
            # Check if secret exists
            db_secret = Secret.query.filter_by(
                path='secret/application/database', 
                type=SecretType.DATABASE
            ).first()
            
            if not db_secret:
                db_secret = Secret(
                    name='Database Credentials',
                    path='secret/application/database',
                    type=SecretType.DATABASE,
                    description='PostgreSQL database credentials'
                )
                db.session.add(db_secret)
                db.session.commit()
            
            # Log access
            log_access(db_secret.id, SecretAction.READ)
            
        except Exception as e:
            logger.error(f"Database error recording secret access: {e}")
        
        return jsonify({
            'status': 'ok',
            'data': masked_data,
            'source': 'vault'
        })
    except Exception as e:
        logger.error(f"Error retrieving database secrets: {e}")
        
        # Log failed access if possible
        try:
            db_secret = Secret.query.filter_by(
                path='secret/application/database', 
                type=SecretType.DATABASE
            ).first()
            if db_secret:
                log_access(db_secret.id, SecretAction.READ, success=False)
        except Exception:
            pass
            
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@vault_api.route('/api/secrets/api')
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
        
        # Record in database
        try:
            # Check if secret exists
            api_secret = Secret.query.filter_by(
                path='secret/application/api', 
                type=SecretType.API
            ).first()
            
            if not api_secret:
                api_secret = Secret(
                    name='API Key',
                    path='secret/application/api',
                    type=SecretType.API,
                    description='External API access key'
                )
                db.session.add(api_secret)
                db.session.commit()
            
            # Log access
            log_access(api_secret.id, SecretAction.READ)
            
        except Exception as e:
            logger.error(f"Database error recording API secret access: {e}")
        
        return jsonify({
            'status': 'ok',
            'data': masked_data,
            'source': 'vault'
        })
    except Exception as e:
        logger.error(f"Error retrieving API secrets: {e}")
        
        # Log failed access if possible
        try:
            api_secret = Secret.query.filter_by(
                path='secret/application/api', 
                type=SecretType.API
            ).first()
            if api_secret:
                log_access(api_secret.id, SecretAction.READ, success=False)
        except Exception:
            pass
            
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@vault_api.route('/api/ssh/generate')
@requires_vault
def generate_ssh_demo(client):
    """Demonstrate SSH certificate generation"""
    try:
        # This is just a demonstration - in a real app, you would:
        # 1. Get the user's public key
        # 2. Sign it with Vault
        # 3. Return the signed certificate
        
        # Check if we're using mock vault
        use_mock = os.environ.get('USE_MOCK_VAULT', 'true').lower() == 'true'
        
        if use_mock:
            # Use the mock client's roles directly
            available_roles = getattr(client, 'roles', {}).get('ssh', ['admin-role', 'dev-role'])
        else:
            # Here we'll just show the SSH roles available from real Vault
            response = requests.get(
                f"{VAULT_ADDR}/v1/ssh/roles",
                headers={"X-Vault-Token": VAULT_TOKEN}
            )
            response.raise_for_status()
            available_roles = response.json().get('data', {}).get('keys', [])
        
        # Record in database
        try:
            # Check if secret exists
            ssh_secret = Secret.query.filter_by(
                path='ssh/roles', 
                type=SecretType.SSH
            ).first()
            
            if not ssh_secret:
                ssh_secret = Secret(
                    name='SSH Roles',
                    path='ssh/roles',
                    type=SecretType.SSH,
                    description='SSH certificate signing roles'
                )
                db.session.add(ssh_secret)
                db.session.commit()
            
            # Log access
            log_access(ssh_secret.id, SecretAction.READ)
            
        except Exception as e:
            logger.error(f"Database error recording SSH secret access: {e}")
        
        return jsonify({
            'status': 'ok',
            'message': 'SSH certificate generation demo',
            'available_roles': available_roles,
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

@vault_api.route('/api/aws/roles')
@requires_vault
def list_aws_roles(client):
    """List available AWS roles"""
    try:
        # Check if we're using mock vault
        use_mock = os.environ.get('USE_MOCK_VAULT', 'true').lower() == 'true'
        
        if use_mock:
            # Use the mock client's roles directly
            available_roles = getattr(client, 'roles', {}).get('aws', ['readonly', 'ec2-admin'])
        else:
            # Real Vault server
            response = requests.get(
                f"{VAULT_ADDR}/v1/aws/roles",
                headers={"X-Vault-Token": VAULT_TOKEN}
            )
            response.raise_for_status()
            available_roles = response.json().get('data', {}).get('keys', [])
        
        # Record in database
        try:
            # Check if secret exists
            aws_secret = Secret.query.filter_by(
                path='aws/roles', 
                type=SecretType.AWS
            ).first()
            
            if not aws_secret:
                aws_secret = Secret(
                    name='AWS Roles',
                    path='aws/roles',
                    type=SecretType.AWS,
                    description='AWS IAM credential generation roles'
                )
                db.session.add(aws_secret)
                db.session.commit()
            
            # Log access
            log_access(aws_secret.id, SecretAction.READ)
            
        except Exception as e:
            logger.error(f"Database error recording AWS secret access: {e}")
        
        return jsonify({
            'status': 'ok',
            'available_roles': available_roles,
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

@vault_api.route('/api/auth/methods')
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
            
            # Record each auth method in database
            try:
                path_clean = path.rstrip('/')  # Remove trailing slash
                role = VaultRole.query.filter_by(name=f"auth-{path_clean}").first()
                
                if not role:
                    role = VaultRole(
                        name=f"auth-{path_clean}",
                        description=f"Authentication method: {details['type']}",
                        policies=details.get('accessor', '')
                    )
                    db.session.add(role)
                    db.session.commit()
            except Exception as e:
                logger.error(f"Database error recording auth method: {e}")
        
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

@vault_api.route('/api/clear-cache')
def clear_cache():
    """Clear the secrets cache"""
    global secrets_cache
    secrets_cache = {}
    return jsonify({
        'status': 'ok',
        'message': 'Cache cleared'
    })

@vault_api.route('/api/database/secrets')
def list_secrets():
    """List secrets from the database"""
    try:
        secrets = Secret.query.all()
        secret_list = []
        
        for secret in secrets:
            # Count access logs
            read_count = AccessLog.query.filter_by(
                secret_id=secret.id, 
                action=SecretAction.READ
            ).count()
            
            last_access = AccessLog.query.filter_by(
                secret_id=secret.id
            ).order_by(AccessLog.timestamp.desc()).first()
            
            secret_list.append({
                'id': secret.id,
                'name': secret.name,
                'path': secret.path,
                'type': secret.type.value,
                'description': secret.description,
                'created_at': secret.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                'read_count': read_count,
                'last_accessed': last_access.timestamp.strftime("%Y-%m-%d %H:%M:%S") if last_access else None
            })
        
        return jsonify({
            'status': 'ok',
            'secrets': secret_list
        })
    except Exception as e:
        logger.error(f"Error listing secrets from database: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@vault_api.route('/api/database/access-logs')
def list_access_logs():
    """List access logs from the database"""
    try:
        logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(100).all()
        log_list = []
        
        for log in logs:
            secret = Secret.query.get(log.secret_id)
            
            log_list.append({
                'id': log.id,
                'secret_name': secret.name if secret else f"Unknown ({log.secret_id})",
                'secret_type': secret.type.value if secret else "unknown",
                'action': log.action.value,
                'timestamp': log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'client_ip': log.client_ip,
                'success': log.success
            })
        
        return jsonify({
            'status': 'ok',
            'logs': log_list
        })
    except Exception as e:
        logger.error(f"Error listing access logs from database: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Page Routes for UI
@vault_api.route('/secrets')
def secrets_page():
    """Secrets management page"""
    vault_status = "Connected" if vault_client() else "Disconnected"
    
    # Get all secrets
    secrets = []
    try:
        db_secrets = Secret.query.all()
        for secret in db_secrets:
            # Count access logs
            read_count = AccessLog.query.filter_by(
                secret_id=secret.id, 
                action=SecretAction.READ
            ).count()
            
            last_access = AccessLog.query.filter_by(
                secret_id=secret.id
            ).order_by(AccessLog.timestamp.desc()).first()
            
            secrets.append({
                'id': secret.id,
                'name': secret.name,
                'path': secret.path,
                'type': secret.type.value,
                'description': secret.description,
                'created_at': secret.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                'read_count': read_count,
                'last_accessed': last_access.timestamp.strftime("%Y-%m-%d %H:%M:%S") if last_access else None
            })
    except Exception as e:
        logger.error(f"Error getting secrets: {e}")
    
    return render_template('secrets.html', 
                          active_page='secrets',
                          vault_status=vault_status,
                          secrets=secrets)

@vault_api.route('/ssh')
def ssh_page():
    """SSH certificates page"""
    vault_status = "Connected" if vault_client() else "Disconnected"
    
    # Get SSH roles
    roles = []
    client = vault_client()
    if client:
        use_mock = os.environ.get('USE_MOCK_VAULT', 'true').lower() == 'true'
        
        if use_mock:
            roles = getattr(client, 'roles', {}).get('ssh', ['admin-role', 'dev-role'])
        else:
            try:
                response = requests.get(
                    f"{VAULT_ADDR}/v1/ssh/roles",
                    headers={"X-Vault-Token": VAULT_TOKEN}
                )
                response.raise_for_status()
                roles = response.json().get('data', {}).get('keys', [])
            except Exception as e:
                logger.error(f"Error getting SSH roles: {e}")
    
    # Get SSH access logs
    ssh_logs = []
    try:
        logs = AccessLog.query.join(Secret).filter(
            Secret.type == SecretType.SSH
        ).order_by(AccessLog.timestamp.desc()).limit(5).all()
        
        for log in logs:
            secret = Secret.query.get(log.secret_id)
            if secret:
                ssh_logs.append({
                    'id': log.id,
                    'secret_name': secret.name,
                    'action': log.action.value,
                    'timestamp': log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'success': log.success
                })
    except Exception as e:
        logger.error(f"Error getting SSH logs: {e}")
    
    return render_template('ssh.html', 
                          active_page='ssh',
                          vault_status=vault_status,
                          ssh_roles=roles,
                          ssh_logs=ssh_logs)

@vault_api.route('/aws')
def aws_page():
    """AWS credentials page"""
    vault_status = "Connected" if vault_client() else "Disconnected"
    
    # Get AWS roles
    roles = []
    client = vault_client()
    if client:
        use_mock = os.environ.get('USE_MOCK_VAULT', 'true').lower() == 'true'
        
        if use_mock:
            roles = getattr(client, 'roles', {}).get('aws', ['readonly', 'ec2-admin'])
        else:
            try:
                response = requests.get(
                    f"{VAULT_ADDR}/v1/aws/roles",
                    headers={"X-Vault-Token": VAULT_TOKEN}
                )
                response.raise_for_status()
                roles = response.json().get('data', {}).get('keys', [])
            except Exception as e:
                logger.error(f"Error getting AWS roles: {e}")
    
    # Get AWS access logs
    aws_logs = []
    try:
        logs = AccessLog.query.join(Secret).filter(
            Secret.type == SecretType.AWS
        ).order_by(AccessLog.timestamp.desc()).limit(5).all()
        
        for log in logs:
            secret = Secret.query.get(log.secret_id)
            if secret:
                aws_logs.append({
                    'id': log.id,
                    'secret_name': secret.name,
                    'action': log.action.value,
                    'timestamp': log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    'success': log.success
                })
    except Exception as e:
        logger.error(f"Error getting AWS logs: {e}")
    
    return render_template('aws.html', 
                          active_page='aws',
                          vault_status=vault_status,
                          aws_roles=roles,
                          aws_logs=aws_logs)

@vault_api.route('/roles')
def roles_page():
    """Roles and policies page"""
    vault_status = "Connected" if vault_client() else "Disconnected"
    
    # Get roles
    roles = []
    try:
        db_roles = VaultRole.query.all()
        for role in db_roles:
            roles.append({
                'id': role.id,
                'name': role.name,
                'description': role.description,
                'policies': role.policies.split(',') if role.policies else [],
                'created_at': role.created_at.strftime("%Y-%m-%d %H:%M:%S")
            })
    except Exception as e:
        logger.error(f"Error getting roles: {e}")
    
    return render_template('roles.html', 
                          active_page='roles',
                          vault_status=vault_status,
                          roles=roles)

@vault_api.route('/activity')
def activity_page():
    """Activity logs page"""
    vault_status = "Connected" if vault_client() else "Disconnected"
    
    # Get logs
    logs = []
    try:
        access_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(50).all()
        for log in access_logs:
            secret = Secret.query.get(log.secret_id)
            logs.append({
                'id': log.id,
                'secret_name': secret.name if secret else f"Unknown ({log.secret_id})",
                'secret_type': secret.type.value if secret else "unknown",
                'action': log.action.value,
                'timestamp': log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'client_ip': log.client_ip,
                'success': log.success
            })
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
    
    return render_template('activity.html', 
                          active_page='activity',
                          vault_status=vault_status,
                          logs=logs)

@vault_api.route('/settings')
def settings_page():
    """Settings page"""
    vault_status = "Connected" if vault_client() else "Disconnected"
    vault_addr = os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200')
    use_mock = os.environ.get('USE_MOCK_VAULT', 'true').lower() == 'true'
    
    return render_template('settings.html', 
                          active_page='settings',
                          vault_status=vault_status,
                          vault_addr=vault_addr,
                          use_mock=use_mock)