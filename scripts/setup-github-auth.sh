#!/bin/bash
# Setup Vault GitHub Authentication

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Vault settings
VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:8200"}
VAULT_TOKEN=${VAULT_TOKEN:-"$(cat /opt/vault/init.txt | grep 'Initial Root Token' | awk '{print $4}')"}

# GitHub Settings
GITHUB_ORG=${GITHUB_ORG:-"your-github-org"}
GITHUB_TEAM=${GITHUB_TEAM:-"vault-admins"}

# Setup Vault CLI
export VAULT_ADDR=$VAULT_ADDR
export VAULT_TOKEN=$VAULT_TOKEN

echo -e "${GREEN}Configuring Vault GitHub Authentication...${NC}"

# Enable GitHub auth if not already enabled
if ! vault auth list | grep -q "^github/"; then
    echo -e "${GREEN}Enabling GitHub auth method...${NC}"
    vault auth enable github
else
    echo -e "${GREEN}GitHub auth method already enabled.${NC}"
fi

# Configure GitHub auth
echo -e "${GREEN}Configuring GitHub organization...${NC}"
vault write auth/github/config organization=$GITHUB_ORG

# Map GitHub team to policies
echo -e "${GREEN}Mapping GitHub teams to policies...${NC}"
vault write auth/github/map/teams/$GITHUB_TEAM value=admin

# Create a policy for developers
echo -e "${GREEN}Creating developer policy...${NC}"
vault write auth/github/map/teams/developers value=app

echo -e "${GREEN}GitHub Authentication configuration complete!${NC}"
echo -e "${GREEN}Users in the '$GITHUB_TEAM' team can now authenticate using their GitHub personal access tokens.${NC}"
echo -e "${GREEN}To authenticate:${NC}"
echo -e "${GREEN}vault login -method=github token=<your-github-token>${NC}"

# Instructions for users
cat <<EOF > /tmp/github_auth_instructions.txt
To authenticate with Vault using GitHub:

1. Create a GitHub personal access token:
   - Go to GitHub Settings > Developer settings > Personal access tokens
   - Generate a new token with the 'read:org' scope
   - Copy the token value

2. Log in to Vault:
   export VAULT_ADDR=$VAULT_ADDR
   vault login -method=github token=<your-github-token>

3. Verify your access:
   vault token lookup

Vault will authenticate you based on your GitHub organization membership.
EOF

echo -e "${GREEN}GitHub authentication instructions saved to /tmp/github_auth_instructions.txt${NC}"
