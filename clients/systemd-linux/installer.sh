#!/bin/bash

# Installation script to set up pull-cert.sh and pull-cert.service
# Creates the script and systemd service for pulling Let's Encrypt certificates from Azure Key Vault
# Uses Red Hat standard paths (/etc/pki/tls/certs/, /etc/pki/tls/private/)

set -e

# Variables
SCRIPT_PATH="/usr/local/bin/pull-cert.sh"
SERVICE_PATH="/etc/systemd/system/pull-cert.service"
CREDENTIALS_DIR="/etc/your-domain-cert"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: This script must be run as root (use sudo)"
  exit 1
fi

# Check if credentials directory exists
if [ ! -d "$CREDENTIALS_DIR" ]; then
  echo "Error: Credentials directory $CREDENTIALS_DIR does not exist"
  echo "Please create $CREDENTIALS_DIR with your-domain-cert-client-id, your-domain-cert-client-secret, and your-domain-cert-tenant-id files"
  exit 1
fi

# Create pull-cert.sh script
echo "Creating $SCRIPT_PATH"
cat > "$SCRIPT_PATH" << 'EOF'
#!/bin/bash

# Configuration
KEY_VAULT_URL="https://your-domain-cert-vault.vault.azure.net"
KEY_SECRET_NAME="your-domain-key"
CERT_SECRET_NAME="your-domain-cert"
PRIVATE_KEY_PATH="/etc/pki/tls/private/your-domain-key.key"
CERT_PATH="/etc/pki/tls/certs/your-domain-cert.crt"
API_VERSION="7.4"

# Note: For Debian-based systems, alternative paths are typically:
# - Certificates: /etc/ssl/certs/your-domain-cert.pem
# - Private Keys: /etc/ssl/private/your-domain-key.pem
# Update paths above if deploying on a Debian-based system.

# Debug: Log mount information
echo "Checking mount status for /etc/pki/tls/private"
mount | grep /etc || echo "No /etc mount found"
findmnt /etc/pki/tls/private || echo "No specific mount for /etc/pki/tls/private"

# Ensure directories exist and are writable
if [ ! -d "/etc/pki/tls/private" ]; then
  echo "Creating directory /etc/pki/tls/private"
  mkdir -p /etc/pki/tls/private || { echo "Error: Failed to create /etc/pki/tls/private"; exit 1; }
  chmod 700 /etc/pki/tls/private || { echo "Error: Failed to set permissions on /etc/pki/tls/private"; exit 1; }
  chown root:root /etc/pki/tls/private || { echo "Error: Failed to set ownership on /etc/pki/tls/private"; exit 1; }
fi

if [ ! -d "/etc/pki/tls/certs" ]; then
  echo "Creating directory /etc/pki/tls/certs"
  mkdir -p /etc/pki/tls/certs || { echo "Error: Failed to create /etc/pki/tls/certs"; exit 1; }
  chmod 755 /etc/pki/tls/certs || { echo "Error: Failed to set permissions on /etc/pki/tls/certs"; exit 1; }
  chown root:root /etc/pki/tls/certs || { echo "Error: Failed to set ownership on /etc/pki/tls/certs"; exit 1; }
fi

# Debug: Test writability
echo "Testing writability of /etc/pki/tls/private"
touch /etc/pki/tls/private/.testwrite 2>/dev/null && rm -f /etc/pki/tls/private/.testwrite && echo "Directory is writable" || echo "Directory is NOT writable"

# Ensure CREDENTIALS_DIRECTORY is set
if [ -z "$CREDENTIALS_DIRECTORY" ]; then
  echo "Error: CREDENTIALS_DIRECTORY not set"
  exit 1
fi

# Load credentials
CLIENT_ID=$(cat "$CREDENTIALS_DIRECTORY/your-domain-cert-client-id")
if [ $? -ne 0 ] || [ -z "$CLIENT_ID" ]; then
  echo "Error: Failed to load CLIENT_ID"
  exit 1
fi

CLIENT_SECRET=$(cat "$CREDENTIALS_DIRECTORY/your-domain-cert-client-secret")
if [ $? -ne 0 ] || [ -z "$CLIENT_SECRET" ]; then
  echo "Error: Failed to load CLIENT_SECRET"
  exit 1
fi

TENANT_ID=$(cat "$CREDENTIALS_DIRECTORY/your-domain-cert-tenant-id")
if [ $? -ne 0 ] || [ -z "$TENANT_ID" ]; then
  echo "Error: Failed to load TENANT_ID"
  exit 1
fi

# Step 1: Get access token using service principal
URL="https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token"
TOKEN_RESPONSE=$(curl -s -X POST "$URL" \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=https%3A%2F%2Fvault.azure.net%2F.default")
TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then
  echo "Error: Failed to obtain access token. Response: $TOKEN_RESPONSE"
  exit 1
fi

# Step 2: Fetch private key from Key Vault
PRIVATE_KEY_RESPONSE=$(curl -s -X GET "${KEY_VAULT_URL}/secrets/${KEY_SECRET_NAME}?api-version=${API_VERSION}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json")
PRIVATE_KEY=$(echo "$PRIVATE_KEY_RESPONSE" | grep -o '"value":"[^"]*' | cut -d'"' -f4 | sed 's/\\n/\n/g')
if [ -z "$PRIVATE_KEY" ]; then
  echo "Error: Failed to retrieve private key. Response: $PRIVATE_KEY_RESPONSE"
  exit 1
fi

# Step 3: Fetch certificate chain from Key Vault (as a secret)
CERT_RESPONSE=$(curl -s -X GET "${KEY_VAULT_URL}/secrets/${CERT_SECRET_NAME}?api-version=${API_VERSION}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json")
CERT_CHAIN=$(echo "$CERT_RESPONSE" | grep -o '"value":"[^"]*' | cut -d'"' -f4 | sed 's/\\n/\n/g')
if [ -z "$CERT_CHAIN" ]; then
  echo "Error: Failed to retrieve certificate chain. Response: $CERT_RESPONSE"
  exit 1
fi

# Step 4: Save private key and certificate chain to files
echo -e "$PRIVATE_KEY" > "$PRIVATE_KEY_PATH" || { echo "Error: Failed to write private key to $PRIVATE_KEY_PATH"; exit 1; }
echo -e "$CERT_CHAIN" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$CERT_PATH" || { echo "Error: Failed to write certificate chain to $CERT_PATH"; exit 1; }

# Step 5: Set permissions for private key
chmod 600 "$PRIVATE_KEY_PATH" || { echo "Error: Failed to set permissions on $PRIVATE_KEY_PATH"; exit 1; }
chown root:root "$PRIVATE_KEY_PATH" || { echo "Error: Failed to set ownership on $PRIVATE_KEY_PATH"; exit 1; }

# Set permissions for certificate
chmod 644 "$CERT_PATH" || { echo "Error: Failed to set permissions on $CERT_PATH"; exit 1; }
chown root:root "$CERT_PATH" || { echo "Error: Failed to set ownership on $CERT_PATH"; exit 1; }

echo "Private key saved to $PRIVATE_KEY_PATH"
echo "Certificate chain saved to $CERT_PATH"

# Step 6: Verify the certificate (optional)
if command -v openssl >/dev/null && openssl x509 -in "$CERT_PATH" -text -noout >/dev/null 2>&1; then
  echo "Certificate is valid"
else
  echo "Warning: Certificate verification failed (openssl not available or invalid PEM)"
fi
EOF

# Set permissions for pull-cert.sh
chmod 755 "$SCRIPT_PATH" || { echo "Error: Failed to set permissions on $SCRIPT_PATH"; exit 1; }
chown root:root "$SCRIPT_PATH" || { echo "Error: Failed to set ownership on $SCRIPT_PATH"; exit 1; }

# Create pull-cert.service
echo "Creating $SERVICE_PATH"
cat > "$SERVICE_PATH" << 'EOF'
[Unit]
Description=Pull Let's Encrypt certificate from Azure Key Vault
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pull-cert.sh
LoadCredentialEncrypted=your-domain-cert-client-id:/etc/your-domain-cert/your-domain-cert-client-id
LoadCredentialEncrypted=your-domain-cert-client-secret:/etc/your-domain-cert/your-domain-cert-client-secret
LoadCredentialEncrypted=your-domain-cert-tenant-id:/etc/your-domain-cert/your-domain-cert-tenant-id
StandardOutput=journal
StandardError=journal
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
ReadWritePaths=/etc/pki/tls/certs /etc/pki/tls/private
ReadOnlyPaths=/etc/your-domain-cert
Environment="CREDENTIALS_DIRECTORY=/run/credentials/pull-cert.service"

[Install]
WantedBy=multi-user.target
EOF

# Set permissions for pull-cert.service
chmod 644 "$SERVICE_PATH" || { echo "Error: Failed to set permissions on $SERVICE_PATH"; exit 1; }
chown root:root "$SERVICE_PATH" || { echo "Error: Failed to set ownership on $SERVICE_PATH"; exit 1; }

# Reload systemd and enable service
echo "Reloading systemd daemon"
systemctl daemon-reload || { echo "Error: Failed to reload systemd daemon"; exit 1; }

echo "Enabling pull-cert.service"
systemctl enable pull-cert.service || { echo "Error: Failed to enable pull-cert.service"; exit 1; }

# Test the service
echo "Starting pull-cert.service to verify installation"
systemctl start pull-cert.service || { echo "Error: Failed to start pull-cert.service"; exit 1; }

# Wait briefly to allow the service to complete
sleep 2

# Check service status
echo "Checking pull-cert.service status"
if systemctl is-active --quiet pull-cert.service; then
  echo "Error: pull-cert.service is still active (should be inactive for Type=oneshot)"
  systemctl status pull-cert.service
  exit 1
else
  if systemctl status pull-cert.service | grep -q "Active: inactive (dead)"; then
    echo "pull-cert.service ran successfully (inactive as expected for oneshot)"
  else
    echo "Error: pull-cert.service failed"
    systemctl status pull-cert.service
    exit 1
  fi
fi

# Verify files were created
echo "Verifying certificate and key files"
if [ -f "$PRIVATE_KEY_PATH" ] && [ -f "$CERT_PATH" ]; then
  echo "Success: Files created at $PRIVATE_KEY_PATH and $CERT_PATH"
  ls -l "$PRIVATE_KEY_PATH" "$CERT_PATH"
else
  echo "Error: One or both files missing: $PRIVATE_KEY_PATH, $CERT_PATH"
  exit 1
fi

echo "Installation complete!"
echo "Next steps:"
echo "- Verify Apache configuration in /etc/httpd/conf.d/ssl.conf points to:"
echo "  SSLCertificateFile /etc/pki/tls/certs/your-domain-cert.crt"
echo "  SSLCertificateKeyFile /etc/pki/tls/private/your-domain-key.key"
echo "- Restart Apache: sudo systemctl restart httpd"
echo "- Check logs if needed: journalctl -u pull-cert.service -n 100"