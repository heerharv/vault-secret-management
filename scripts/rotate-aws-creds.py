#!/usr/bin/env python3
"""
Rotate AWS credentials using HashiCorp Vault

This script:
1. Retrieves temporary AWS credentials from Vault
2. Updates an AWS profile in ~/.aws/credentials
3. Revokes the previous lease if it exists
"""

import argparse
import configparser
import os
import json
import sys
import requests
from pathlib import Path

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Rotate AWS credentials using HashiCorp Vault')
    parser.add_argument('--vault-addr', default=os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8200'),
                        help='Vault server address (default: http://127.0.0.1:8200)')
    parser.add_argument('--vault-token', default=os.environ.get('VAULT_TOKEN'),
                        help='Vault token (default: from VAULT_TOKEN env variable)')
    parser.add_argument('--aws-role', default='readonly',
                        help='AWS role in Vault (default: readonly)')
    parser.add_argument('--profile', default='vault',
                        help='AWS profile to update (default: vault)')
    parser.add_argument('--lease-file', default=str(Path.home() / '.vault-aws-lease'),
                        help='File to store the lease ID (default: ~/.vault-aws-lease)')
    
    args = parser.parse_args()
    
    if not args.vault_token:
        sys.exit("Error: Vault token not provided. Set VAULT_TOKEN env variable or use --vault-token")
    
    return args

def get_aws_credentials(vault_addr, vault_token, aws_role):
    """Get temporary AWS credentials from Vault"""
    url = f"{vault_addr}/v1/aws/creds/{aws_role}"
    headers = {"X-Vault-Token": vault_token}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        sys.exit(f"Error retrieving AWS credentials from Vault: {e}")

def update_aws_profile(profile, access_key, secret_key, region='us-east-1'):
    """Update AWS credentials file with new credentials"""
    aws_creds_path = Path.home() / '.aws' / 'credentials'
    aws_creds_path.parent.mkdir(exist_ok=True)
    
    config = configparser.ConfigParser()
    if aws_creds_path.exists():
        config.read(aws_creds_path)
    
    if not config.has_section(profile):
        config.add_section(profile)
    
    config[profile]['aws_access_key_id'] = access_key
    config[profile]['aws_secret_access_key'] = secret_key
    config[profile]['region'] = region
    
    with open(aws_creds_path, 'w') as f:
        config.write(f)
    
    os.chmod(aws_creds_path, 0o600)  # Set secure permissions
    print(f"Updated AWS profile '{profile}' with new credentials")

def revoke_previous_lease(vault_addr, vault_token, lease_file):
    """Revoke previous Vault lease if it exists"""
    if not os.path.exists(lease_file):
        return
    
    try:
        with open(lease_file, 'r') as f:
            lease_data = json.load(f)
            lease_id = lease_data.get('lease_id')
            
        if lease_id:
            url = f"{vault_addr}/v1/sys/leases/revoke"
            headers = {"X-Vault-Token": vault_token}
            data = {"lease_id": lease_id}
            
            response = requests.put(url, headers=headers, json=data)
            if response.status_code == 204:
                print(f"Successfully revoked previous lease: {lease_id}")
            else:
                print(f"Warning: Failed to revoke previous lease: {response.text}")
    except Exception as e:
        print(f"Warning: Error revoking previous lease: {e}")

def save_lease_data(lease_file, lease_data):
    """Save lease data to file"""
    try:
        with open(lease_file, 'w') as f:
            json.dump(lease_data, f)
        os.chmod(lease_file, 0o600)  # Set secure permissions
        print(f"Saved lease data to {lease_file}")
    except Exception as e:
        print(f"Warning: Failed to save lease data: {e}")

def main():
    """Main function"""
    args = parse_args()
    
    # Revoke previous lease if it exists
    revoke_previous_lease(args.vault_addr, args.vault_token, args.lease_file)
    
    # Get new credentials from Vault
    credentials = get_aws_credentials(args.vault_addr, args.vault_token, args.aws_role)
    
    # Extract credentials
    access_key = credentials['data']['access_key']
    secret_key = credentials['data']['secret_key']
    lease_id = credentials['lease_id']
    lease_duration = credentials['lease_duration']
    
    # Update AWS credentials file
    update_aws_profile(args.profile, access_key, secret_key)
    
    # Save lease information for future revocation
    lease_data = {
        'lease_id': lease_id,
        'lease_duration': lease_duration,
        'role': args.aws_role,
        'profile': args.profile
    }
    save_lease_data(args.lease_file, lease_data)
    
    print(f"AWS credentials for role '{args.aws_role}' will be valid for {lease_duration} seconds")
    print(f"AWS CLI profile '{args.profile}' is ready to use")

if __name__ == "__main__":
    main()
