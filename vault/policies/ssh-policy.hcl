# SSH policy for generating SSH certificates

# Read system health check
path "sys/health" {
  capabilities = ["read"]
}

# Generate SSH certificates
path "ssh/sign/*" {
  capabilities = ["create", "update"]
}

# List SSH roles
path "ssh/roles" {
  capabilities = ["list"]
}

# Read SSH roles
path "ssh/roles/*" {
  capabilities = ["read"]
}
