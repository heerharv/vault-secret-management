"""
Mock Vault server for demonstration purposes
"""

import os
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class MockVaultClient:
    """
    A mock implementation of hvac.Client to demonstrate Vault functionality
    without requiring an actual Vault server.
    """
    
    def __init__(self, url=None, token=None):
        self.url = url
        self.token = token
        self.data = {
            'secret/application/database': {
                'data': {
                    'username': 'db_user',
                    'password': 'demo_password'
                },
                'metadata': {
                    'created_time': datetime.utcnow().isoformat()
                }
            },
            'secret/application/api': {
                'data': {
                    'api_key': 'api12345678demo'
                },
                'metadata': {
                    'created_time': datetime.utcnow().isoformat()
                }
            }
        }
        self.auth_methods = {
            'token/': {
                'type': 'token',
                'description': 'Token-based authentication'
            },
            'github/': {
                'type': 'github',
                'description': 'GitHub organization-based authentication'
            },
            'ldap/': {
                'type': 'ldap',
                'description': 'LDAP directory authentication'
            }
        }
        self.roles = {
            'ssh': ['admin-role', 'dev-role'],
            'aws': ['readonly', 'ec2-admin']
        }
        
        logger.info("Initialized mock Vault client")
    
    def is_authenticated(self):
        """Check if token is valid"""
        return self.token == os.environ.get('MOCK_VAULT_TOKEN', 'mock-token')
    
    @property
    def secrets(self):
        """Return secrets namespace"""
        return self
    
    @property
    def kv(self):
        """Return KV namespace"""
        return self
    
    @property
    def v2(self):
        """Return KV v2 namespace"""
        return self
    
    @property
    def sys(self):
        """Return sys namespace"""
        return self
    
    @property
    def aws(self):
        """Return AWS namespace for secrets engine"""
        return self
    
    def read_secret_version(self, path, mount_point=None):
        """Read a secret from the mock store"""
        full_path = f"{mount_point}/{path}" if mount_point else path
        
        if full_path in self.data:
            return {
                'data': {
                    'data': self.data[full_path]['data'],
                    'metadata': self.data[full_path]['metadata']
                }
            }
        
        raise Exception(f"Secret not found at {full_path}")
    
    def read_health_status(self, method=None):
        """Return mock health status"""
        return {
            'initialized': True,
            'sealed': False,
            'standby': False,
            'performance_standby': False,
            'replication_performance_mode': 'disabled',
            'replication_dr_mode': 'disabled',
            'server_time_utc': int(datetime.utcnow().timestamp()),
            'version': '1.10.3',
            'cluster_name': 'vault-demo-cluster',
            'cluster_id': 'mock-cluster-123456'
        }
    
    def list_auth_methods(self):
        """Return mock auth methods"""
        return {
            'data': self.auth_methods
        }
    
    def generate_credentials(self, name):
        """Generate mock AWS credentials"""
        if name in self.roles['aws']:
            return {
                'data': {
                    'access_key': f'AKIA{name.upper()}1234567',
                    'secret_key': 'mock-secret-key-for-demonstration-only'
                },
                'lease_duration': 3600
            }
        
        raise Exception(f"Role '{name}' not found")

# Create a mock HTTP response for the Vault API
class MockResponse:
    """Mock requests.Response"""
    
    def __init__(self, data, status_code=200):
        self.data = data
        self.status_code = status_code
    
    def json(self):
        """Return JSON data"""
        return self.data
    
    def raise_for_status(self):
        """Check HTTP status"""
        if self.status_code >= 400:
            raise Exception(f"HTTP Error: {self.status_code}")