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