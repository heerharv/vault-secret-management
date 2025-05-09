# Vault Secret Management System
A DevSecOps project demonstrating secure secrets management with HashiCorp Vault and Ansible for credential rotation and access control.
## Overview
This project showcases a complete secrets management solution using HashiCorp Vault as the central secure storage system, with Ansible automation for deployment and configuration. The system includes a Flask web application that demonstrates how to integrate Vault into a real-world application for managing sensitive credentials.
## Features
- **Centralized Secrets Management**: Store all sensitive credentials (database passwords, API keys, certificates) in a secure vault
- **Dynamic AWS Credentials**: Generate temporary AWS IAM credentials with automatic expiration
- **SSH Certificate Authority**: Issue short-lived SSH certificates instead of distributing static SSH keys
- **Role-Based Access Control**: Manage permissions with fine-grained policies
- **Integration with Identity Providers**: Connect to GitHub or LDAP for authentication
- **Audit Logging**: Track all secret access for compliance and security monitoring
- **Web Dashboard**: Professional UI for managing secrets with minimal security expertise
## Technology Stack
- **HashiCorp Vault**: Core secrets management platform
- **Ansible**: Automation for deployment, configuration, and credential rotation
- **Flask**: Web application framework for the demonstration UI
- **SQLAlchemy**: ORM for database integration
- **PostgreSQL/SQLite**: Database options for storing non-sensitive metadata
- **Python**: Primary programming language
## Project Structure
.
├── ansible/ # Ansible playbooks for automation
├── demo/ # Flask demo application
│ ├── app.py # Application entry point
│ ├── main.py # Application configuration
│ ├── models.py # Database models
│ ├── routes.py # API endpoints and routes
│ ├── mock_vault.py # Mock implementation for testing
│ ├── static/ # CSS, JS, and images
│ ├── templates/ # HTML templates
│ └── migrations/ # Database migrations
├── scripts/ # Utility scripts
│ └── rotate-aws-creds.py # AWS credential rotation
├── vault/ # Vault configuration
│ ├── config.hcl # Server configuration
│ └── policies/ # Access control policies
└── setup.sh # Setup script

## Installation
### Prerequisites
- Python 3.8+
- Ansible 2.9+
- HashiCorp Vault (optional for demo mode)
- PostgreSQL (optional, SQLite fallback available)
### Setup
1. Clone the repository:
git clone https://github.com/heerharv/vault-secret-management.git
cd vault-secret-management

2. Install dependencies:
pip install -r requirements.txt

3. Set up environment variables (or create a `.env` file):
Core settings
FLASK_APP=demo.app
FLASK_ENV=development

Database settings
DATABASE_URL=postgresql://user:password@localhost/vault_demo

Vault settings
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=your_token

For demo mode without a real Vault server
USE_MOCK_VAULT=true

4. Initialize the database:
flask db upgrade

5. Start the application:
flask run

## Usage
### Demo Application
The Flask demo application provides a web interface for:
- Managing database credentials and API keys
- Generating temporary AWS access credentials
- Issuing SSH certificates
- Viewing audit logs of all secret access
Access the demo at http://localhost:5000 after starting the application.
### Ansible Integration
The Ansible playbooks demonstrate:
- Automating Vault deployment and configuration
- Retrieving dynamic secrets during playbook execution
- Rotating credentials for services and databases
To run the demo Ansible playbook:
ansible-playbook ansible/vault-setup.yml

### AWS Credential Rotation
The project includes a script for rotating AWS credentials:
python scripts/rotate-aws-creds.py --role readonly --profile default

## Security Considerations
- The demo application uses a mock Vault client by default for simplified testing
- For production use, replace mock implementations with a real Vault server
- Properly secure your Vault server with appropriate authentication methods
- Configure audit logging for all Vault interactions
- Regularly rotate the Vault root token and unseal keys
## Cross-Platform Compatibility
- The application supports both PostgreSQL (production) and SQLite (development/Windows)
- Configuration auto-detects the platform and adapts settings accordingly
- All scripts work on Linux, macOS, and Windows systems
## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
## License
This project is licensed under the MIT License - see the LICENSE file for details.
You can add this README.md file to your repository by saving it as README.md in your project's root directory, then committing and pushing it to GitHub:

# Save the content above to README.md in your project root
# Add and commit
git add README.md
git commit -m "Add comprehensive project documentation"
# Push to GitHub
git push origin main
This README provides a professional overview of your project, explains its features and structure, and includes installation and usage instructions.
 
