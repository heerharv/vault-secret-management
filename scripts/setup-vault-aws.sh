#!/bin/bash
# Setup Vault AWS Secret Engine

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Vault settings
VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:8200"}
VAULT_TOKEN=${VAULT_TOKEN:-"$(cat /opt/vault/init.txt | grep 'Initial Root Token' | awk '{print $4}')"}

# AWS Settings - these should be provided securely in a production environment
# For demo purposes, we're using environment variables
AWS_ACCESS_KEY=${AWS_ACCESS_KEY:-""}
AWS_SECRET_KEY=${AWS_SECRET_KEY:-""}
AWS_REGION=${AWS_REGION:-"us-east-1"}

# Check if AWS credentials are provided
if [ -z "$AWS_ACCESS_KEY" ] || [ -z "$AWS_SECRET_KEY" ]; then
    echo -e "${RED}AWS credentials are not set. Please provide AWS_ACCESS_KEY and AWS_SECRET_KEY.${NC}"
    exit 1
fi

# Setup Vault CLI
export VAULT_ADDR=$VAULT_ADDR
export VAULT_TOKEN=$VAULT_TOKEN

echo -e "${GREEN}Configuring Vault AWS Secrets Engine...${NC}"

# Enable AWS secrets engine if not already enabled
if ! vault secrets list | grep -q "^aws/"; then
    echo -e "${GREEN}Enabling AWS secrets engine...${NC}"
    vault secrets enable -path=aws aws
else
    echo -e "${GREEN}AWS secrets engine already enabled.${NC}"
fi

# Configure AWS secrets engine
echo -e "${GREEN}Configuring AWS credentials...${NC}"
vault write aws/config/root \
    access_key=$AWS_ACCESS_KEY \
    secret_key=$AWS_SECRET_KEY \
    region=$AWS_REGION

# Create a role for readonly access
echo -e "${GREEN}Creating read-only IAM role...${NC}"
vault write aws/roles/readonly \
    credential_type=iam_user \
    policy_document='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:Describe*",
                    "s3:List*",
                    "s3:Get*"
                ],
                "Resource": "*"
            }
        ]
    }'

# Create a role for admin access
echo -e "${GREEN}Creating admin IAM role...${NC}"
vault write aws/roles/ec2-admin \
    credential_type=iam_user \
    policy_document='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:*"
                ],
                "Resource": "*"
            }
        ]
    }'

# Create a policy for accessing AWS secrets
echo -e "${GREEN}Creating AWS access policy...${NC}"
vault policy write aws-policy - <<EOF
# Read system health check
path "sys/health" {
  capabilities = ["read"]
}

# Read AWS credentials
path "aws/creds/*" {
  capabilities = ["read"]
}

# List available roles
path "aws/roles" {
  capabilities = ["list"]
}

# Read specific AWS role
path "aws/roles/*" {
  capabilities = ["read"]
}
EOF

echo -e "${GREEN}AWS Secrets Engine configuration complete!${NC}"
echo -e "${GREEN}You can now generate AWS credentials using:${NC}"
echo -e "${GREEN}vault read aws/creds/readonly${NC}"
echo -e "${GREEN}vault read aws/creds/ec2-admin${NC}"
