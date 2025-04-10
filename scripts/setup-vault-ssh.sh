#!/bin/bash
# Setup Vault SSH Secret Engine

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Vault settings
VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:8200"}
VAULT_TOKEN=${VAULT_TOKEN:-"$(cat /opt/vault/init.txt | grep 'Initial Root Token' | awk '{print $4}')"}

# SSH Settings
SSH_MOUNT_POINT=${SSH_MOUNT_POINT:-"ssh"}
SSH_ADMIN_ROLE=${SSH_ADMIN_ROLE:-"admin-role"}
SSH_DEV_ROLE=${SSH_DEV_ROLE:-"dev-role"}

# Setup Vault CLI
export VAULT_ADDR=$VAULT_ADDR
export VAULT_TOKEN=$VAULT_TOKEN

echo -e "${GREEN}Configuring Vault SSH Secrets Engine...${NC}"

# Enable SSH secrets engine if not already enabled
if ! vault secrets list | grep -q "^$SSH_MOUNT_POINT/"; then
    echo -e "${GREEN}Enabling SSH secrets engine...${NC}"
    vault secrets enable -path=$SSH_MOUNT_POINT ssh
else
    echo -e "${GREEN}SSH secrets engine already enabled.${NC}"
fi

# Generate CA key pair
echo -e "${GREEN}Generating SSH CA key pair...${NC}"
vault write -f $SSH_MOUNT_POINT/config/ca

# Create a CA certificate
echo -e "${GREEN}Creating SSH CA certificate...${NC}"
vault read -field=public_key $SSH_MOUNT_POINT/config/ca > /tmp/ssh_ca.pub

echo -e "${GREEN}SSH CA public key saved to /tmp/ssh_ca.pub${NC}"
echo -e "${GREEN}To configure trusted CA on target hosts, run:${NC}"
echo -e "${GREEN}echo '@cert-authority * $(cat /tmp/ssh_ca.pub)' >> ~/.ssh/known_hosts${NC}"

# Create a role for admin users
echo -e "${GREEN}Creating admin SSH role...${NC}"
vault write $SSH_MOUNT_POINT/roles/$SSH_ADMIN_ROLE -<<EOF
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "allowed_extensions": "permit-pty,permit-port-forwarding,permit-agent-forwarding",
  "default_extensions": {
    "permit-pty": ""
  },
  "key_type": "ca",
  "default_user": "ubuntu",
  "ttl": "24h"
}
EOF

# Create a role for developers
echo -e "${GREEN}Creating developer SSH role...${NC}"
vault write $SSH_MOUNT_POINT/roles/$SSH_DEV_ROLE -<<EOF
{
  "allow_user_certificates": true,
  "allowed_users": "dev,webapp",
  "allowed_extensions": "permit-pty",
  "default_extensions": {
    "permit-pty": ""
  },
  "key_type": "ca",
  "default_user": "dev",
  "ttl": "8h"
}
EOF

# Create a policy for SSH access
echo -e "${GREEN}Creating SSH access policy...${NC}"
vault policy write ssh-policy - <<EOF
# Read system health check
path "sys/health" {
  capabilities = ["read"]
}

# Generate SSH certificates
path "$SSH_MOUNT_POINT/sign/*" {
  capabilities = ["create", "update"]
}

# List SSH roles
path "$SSH_MOUNT_POINT/roles" {
  capabilities = ["list"]
}

# Read SSH roles
path "$SSH_MOUNT_POINT/roles/*" {
  capabilities = ["read"]
}
EOF

echo -e "${GREEN}SSH Secrets Engine configuration complete!${NC}"
echo -e "${GREEN}You can now sign SSH keys using:${NC}"
echo -e "${GREEN}vault write $SSH_MOUNT_POINT/sign/$SSH_ADMIN_ROLE public_key=@/path/to/your/key.pub${NC}"

# Instructions for host configuration
cat <<EOF > /tmp/ssh_host_instructions.txt
To configure a host to trust the Vault SSH CA:

1. Copy the CA public key to the host:
   scp /tmp/ssh_ca.pub user@target-host:/tmp/

2. Add the CA public key to trusted CAs:
   ssh user@target-host "cat /tmp/ssh_ca.pub >> ~/.ssh/trusted-user-ca-keys.pub"

3. Configure SSH server to use the CA key for authentication:
   ssh user@target-host "echo 'TrustedUserCAKeys ~/.ssh/trusted-user-ca-keys.pub' | sudo tee -a /etc/ssh/sshd_config"

4. Restart SSH service:
   ssh user@target-host "sudo systemctl restart sshd"

Now the host will trust any SSH certificate signed by Vault.
EOF

echo -e "${GREEN}Host configuration instructions saved to /tmp/ssh_host_instructions.txt${NC}"
