# Application policy
# Provides read-only access to specific secrets

# Read system health
path "sys/health" {
  capabilities = ["read"]
}

# Read application secrets
path "secret/data/application/*" {
  capabilities = ["read"]
}

# List secrets
path "secret/metadata/application/*" {
  capabilities = ["list"]
}
