#!/bin/bash
# Vault setup script

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Vault setup...${NC}"

# Ensure Vault is installed
if ! command -v vault &> /dev/null; then
    echo -e "${RED}Vault is not installed. Please install Vault first.${NC}"
    exit 1
fi

# Create necessary directories
mkdir -p /opt/vault/data
mkdir -p /opt/vault/logs
mkdir -p /opt/vault/policies

# Copy configuration
cp config.hcl /opt/vault/config.hcl
cp -r policies/ /opt/vault/

# Set permissions
chmod 700 /opt/vault/data
chmod 700 /opt/vault/logs

# Start Vault in dev mode for simplicity
# In production, you would use systemd service
echo -e "${GREEN}Starting Vault server...${NC}"
vault server -config=/opt/vault/config.hcl > /opt/vault/logs/vault.log 2>&1 &
VAULT_PID=$!

echo -e "${GREEN}Waiting for Vault to start...${NC}"
sleep 5

# Initialize Vault
export VAULT_ADDR='http://127.0.0.1:8200'

# Check if Vault is already initialized
if vault status | grep -q "Initialized.*true"; then
    echo -e "${GREEN}Vault is already initialized.${NC}"
else
    echo -e "${GREEN}Initializing Vault...${NC}"
    vault operator init > /opt/vault/init.txt
    
    # Extract keys and token
    UNSEAL_KEY1=$(grep "Unseal Key 1" /opt/vault/init.txt | awk '{print $4}')
    UNSEAL_KEY2=$(grep "Unseal Key 2" /opt/vault/init.txt | awk '{print $4}')
    UNSEAL_KEY3=$(grep "Unseal Key 3" /opt/vault/init.txt | awk '{print $4}')
    ROOT_TOKEN=$(grep "Initial Root Token" /opt/vault/init.txt | awk '{print $4}')
    
    # Secure the init file
    chmod 600 /opt/vault/init.txt
    
    # Unseal Vault
    echo -e "${GREEN}Unsealing Vault...${NC}"
    vault operator unseal $UNSEAL_KEY1
    vault operator unseal $UNSEAL_KEY2
    vault operator unseal $UNSEAL_KEY3
    
    # Login
    echo -e "${GREEN}Logging in to Vault...${NC}"
    vault login $ROOT_TOKEN
fi

# Enable secrets engines
echo -e "${GREEN}Enabling secrets engines...${NC}"
vault secrets enable -path=secret kv-v2
vault secrets enable aws
vault secrets enable ssh

# Create policies
echo -e "${GREEN}Creating policies...${NC}"
vault policy write admin /opt/vault/policies/admin-policy.hcl
vault policy write app /opt/vault/policies/app-policy.hcl
vault policy write aws /opt/vault/policies/aws-policy.hcl
vault policy write ssh /opt/vault/policies/ssh-policy.hcl

# Create some example secrets
echo -e "${GREEN}Creating example secrets...${NC}"
vault kv put secret/application/database username=db_user password=db_password
vault kv put secret/application/api api_key=example_api_key

echo -e "${GREEN}Vault setup complete!${NC}"
echo -e "${GREEN}Root token and unseal keys are stored in /opt/vault/init.txt${NC}"
echo -e "${GREEN}Please save these securely in a production environment!${NC}"
echo -e "${GREEN}Vault server running with PID: $VAULT_PID${NC}"
