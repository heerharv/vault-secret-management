# AWS policy for accessing AWS secrets

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
