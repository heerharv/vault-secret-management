# Secure Secrets Management with HashiCorp Vault and Ansible

This project demonstrates how to implement secure secrets management using HashiCorp Vault and Ansible. It provides practical examples of credential rotation, access control, and secrets management in a DevSecOps environment.

## Features

- Vault server setup and configuration
- Ansible integration with Vault for secrets retrieval
- SSH certificate generation via Vault
- AWS IAM credential rotation
- Authentication integration with GitHub and LDAP
- PostgreSQL database integration for logging and tracking
- Web-based dashboard for secrets management

## Project Structure

```
.
├── ansible/              # Ansible playbooks and configurations
│   ├── roles/            # Ansible roles for Vault setup
│   └── *.yml             # Task-specific playbooks
├── vault/                # Vault configuration files
│   ├── policies/         # Access control policies
│   └── config.hcl        # Main Vault configuration
├── demo/                 # Flask-based demonstration application
│   ├── templates/        # Web UI templates
│   ├── migrations/       # Database migrations
│   ├── app.py            # Application entry point
│   ├── main.py           # Flask app configuration
│   ├── models.py         # Database models
│   ├── routes.py         # API and web endpoints
│   └── mock_vault.py     # Mock implementation for demos
├── scripts/              # Utility scripts for setup and rotation
├── .vscode/              # VS Code configuration
├── .env                  # Environment variables (create from .env.example)
└── setup.sh              # Setup script for development environment
```

## VS Code Development Setup

This project includes comprehensive VS Code support, making it easy to develop, run, and debug the application.

### Prerequisites

- Python 3.9+
- PostgreSQL
- VS Code with Python extension

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/vault-ansible-demo.git
   cd vault-ansible-demo
   ```

2. Run the setup script to create a virtual environment and set up the database:
   ```bash
   ./setup.sh
   ```

3. Open the project in VS Code:
   ```bash
   code .
   ```

4. Use the provided VS Code launch configurations to run or debug the application.

### Environment Variables

Create a `.env` file in the project root with the following values:

```
DATABASE_URL=postgresql://localhost:5432/vault_demo
FLASK_SECRET_KEY=your-secret-key
VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=your-vault-token
USE_MOCK_VAULT=true  # Set to false to use a real Vault server
```

### Running the Application

You can run the application in several ways:

1. **VS Code Debug**: Use the "Flask App" launch configuration
2. **Terminal**: From the project root, run:
   ```bash
   cd demo
   flask run --host=0.0.0.0
   ```
3. **Production**: Use gunicorn:
   ```bash
   gunicorn -w 4 'demo.app:app' -b 0.0.0.0:5000
   ```

## Real-World Deployment

For a production deployment, you should:

1. Set up a real Vault server (not the mock implementation)
2. Secure your database with strong credentials
3. Use HTTPS for all connections
4. Implement proper user authentication
5. Store sensitive environment variables securely

### Using a Real Vault Server

To use a real Vault server:

1. Install and configure HashiCorp Vault:
   ```bash
   # See vault/setup.sh for an example setup
   ```

2. Set environment variables to connect to your Vault server:
   ```
   USE_MOCK_VAULT=false
   VAULT_ADDR=https://your-vault-server:8200
   VAULT_TOKEN=your-secure-token
   ```

3. Configure appropriate policies:
   ```bash
   # See vault/policies/ directory for example policies
   ```

### Deploying with Docker

You can containerize the application using:

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY . .
RUN pip install -r demo/requirements.txt
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "demo.app:app", "-b", "0.0.0.0:5000"]
```

### Deploying with Ansible

The included Ansible playbooks can be used to automate deployment:

```bash
ansible-playbook -i ansible/inventory.ini ansible/vault-setup.yml
```

See the ansible/ directory for more deployment options.

