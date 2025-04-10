#!/bin/bash
# Setup Vault LDAP Authentication

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Vault settings
VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:8200"}
VAULT_TOKEN=${VAULT_TOKEN:-"$(cat /opt/vault/init.txt | grep 'Initial Root Token' | awk '{print $4}')"}

# LDAP Settings
LDAP_URL=${LDAP_URL:-"ldap://ldap.example.com:389"}
LDAP_BINDDN=${LDAP_BINDDN:-"cn=vault,ou=service accounts,dc=example,dc=com"}
LDAP_BINDPASS=${LDAP_BINDPASS:-"ldappassword"}
LDAP_USERDN=${LDAP_USERDN:-"ou=users,dc=example,dc=com"}
LDAP_USERATTR=${LDAP_USERATTR:-"uid"}
LDAP_GROUPDN=${LDAP_GROUPDN:-"ou=groups,dc=example,dc=com"}

# Check if LDAP bind password is provided
if [ -z "$LDAP_BINDPASS" ]; then
    echo -e "${RED}LDAP bind password is not set. Please provide LDAP_BINDPASS.${NC}"
    exit 1
fi

# Setup Vault CLI
export VAULT_ADDR=$VAULT_ADDR
export VAULT_TOKEN=$VAULT_TOKEN

echo -e "${GREEN}Configuring Vault LDAP Authentication...${NC}"

# Enable LDAP auth if not already enabled
if ! vault auth list | grep -q "^ldap/"; then
    echo -e "${GREEN}Enabling LDAP auth method...${NC}"
    vault auth enable ldap
else
    echo -e "${GREEN}LDAP auth method already enabled.${NC}"
fi

# Configure LDAP auth
echo -e "${GREEN}Configuring LDAP connection...${NC}"
vault write auth/ldap/config \
    url="$LDAP_URL" \
    binddn="$LDAP_BINDDN" \
    bindpass="$LDAP_BINDPASS" \
    userdn="$LDAP_USERDN" \
    userattr="$LDAP_USERATTR" \
    groupdn="$LDAP_GROUPDN" \
    groupfilter="(&(objectClass=groupOfNames)(member={{.UserDN}}))" \
    insecure_tls=true

# Map LDAP groups to policies
echo -e "${GREEN}Mapping LDAP groups to policies...${NC}"
vault write auth/ldap/groups/vault-admins policies=admin
vault write auth/ldap/groups/developers policies=app
vault write auth/ldap/groups/operations policies=aws-policy,ssh-policy

echo -e "${GREEN}LDAP Authentication configuration complete!${NC}"
echo -e "${GREEN}Users can now authenticate using their LDAP credentials.${NC}"
echo -e "${GREEN}To authenticate:${NC}"
echo -e "${GREEN}vault login -method=ldap username=<username> password=<password>${NC}"

# Instructions for users
cat <<EOF > /tmp/ldap_auth_instructions.txt
To authenticate with Vault using LDAP:

1. Log in to Vault:
   export VAULT_ADDR=$VAULT_ADDR
   vault login -method=ldap username=<your-username> password=<your-password>

2. Verify your access:
   vault token lookup

Vault will authenticate you based on your LDAP group memberships:
- Members of 'vault-admins' group receive admin policy
- Members of 'developers' group receive app policy
- Members of 'operations' group receive aws-policy and ssh-policy

If you are not authorized, check with your administrator about your LDAP group memberships.
EOF

echo -e "${GREEN}LDAP authentication instructions saved to /tmp/ldap_auth_instructions.txt${NC}"
