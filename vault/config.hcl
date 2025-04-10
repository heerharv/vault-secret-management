# Vault server configuration

storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1  # Disable for development only, enable TLS in production
}

# API address
api_addr = "http://127.0.0.1:8200"

# Enable UI
ui = true

# For development only - disable mlock in production
disable_mlock = true
