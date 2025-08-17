# Pulling Certificates to Servers

This document describes how to configure servers to pull Let's Encrypt wildcard certificates (`*.example.com`) and their private keys from Azure Key Vault (`https://example-vault.vault.azure.net/`) for use in TLS applications (e.g., Apache, Nginx). It includes creating Azure service principal credentials, pulling certificates and keys, and securely storing credentials using systemd with TPM-backed encryption.

## Overview

Servers pull two secrets from Key Vault:
- **Certificate Chain**: Stored as `example-cert`, containing the certificate chain (leaf + intermediates).
- **Private Key**: Stored as `example-key`, containing the private key.

The provided `pull-cert.sh` script retrieves these secrets and saves them to Red Hat standard paths:
- `/etc/pki/tls/certs/example-cert.crt` (certificate chain).
- `/etc/pki/tls/private/example-key.key` (private key).

The script uses Azure credentials (service principal) to authenticate with Key Vault, and systemd manages the script execution and credential storage, optionally encrypted with TPM.

## Prerequisites

- **Server Access**: A Linux server (e.g., CentOS, Rocky Linux) with `systemd` and TPM 2.0 support (for secure credential storage).
- **Azure CLI**: Installed for credential creation (`az`).
- **Key Vault Permissions**: Access to `example-vault` in subscription `subscription-id-uuid`.
- **Dependencies**: `curl`, `sed`, `openssl` (optional for verification).
- **Credentials Directory**: `/etc/example-cert/` to store encrypted credentials.

## Creating Service Principal Credentials

To pull secrets from Key Vault, create a service principal with the "Key Vault Secrets User" role.

### Steps

1. **Create Service Principal**:
   Run the following Azure CLI command to create a service principal named `example-cert-puller`:
   ```bash
   az ad sp create-for-rbac \
     --name "example-cert-puller" \
     --role "Key Vault Secrets User" \
     --scopes "/subscriptions/subscription-id-uuid/resourceGroups/example-rg/providers/Microsoft.KeyVault/vaults/example-vault"
   Example output:
   ```json
   {
     "appId": "client-id-uuid",
     "displayName": "example-cert-puller",
     "password": "client-secret-base64",
     "tenant": "tenant-id-uuid"
   }
   ```

2. **Store Credentials:**
The credentials (appId, password, tenant) are used by the pull-cert.sh script. These will be stored securely on the server (see "Storing Credentials with Systemd and TPM" below).

3. **Verify Permissions:**
Confirm the service principal has access:

   ```bash
   az role assignment list \
     --assignee client-id-uuid \
     --scope "/subscriptions/subscription-id-uuid/resourceGroups/example-rg/providers/Microsoft.KeyVault/vaults/example-vault" \
     --query "[?roleDefinitionName=='Key Vault Secrets User'].roleDefinitionName" -o tsv
   ```
   Expected: `Key Vault Secrets User`.

# Pulling Certificates and Keys
The pull-cert.sh script retrieves the certificate and private key from Key Vault and saves them to the server.

## Installation
Use the provided installation script (install-pull-cert.sh) to set up the script and systemd service:
   1. **Save the Installation Script:**
   ```bash
   vi install-pull-cert.sh
   ```
   Paste the script from the repository (or see below for reference).
   Make executable:
   ```bash
   chmod +x install-pull-cert.sh
   ```
2. **Ensure Credentials Directory:**
Create /etc/example-cert/ and store credentials (if not using TPM yet):
   ```bash
   sudo mkdir -p /etc/example-cert
   echo "client-id-uuid" | sudo tee /etc/example-cert/example-cert-client-id
   echo "client-secret-base64" | sudo tee /etc/example-cert/example-cert-client-secret
   echo "tenant-id-uuid" | sudo tee /etc/example-cert/example-cert-tenant-id
   sudo chmod 600 /etc/example-cert/*
   sudo chown root:root /etc/example-cert/*
   ```

3. **Run Installation:**
   ```bash
   sudo ./install-pull-cert.sh
   ```
   
   This creates:
   - `/usr/local/bin/pull-cert.sh`
   - `/etc/systemd/system/pull-cert.service`
   - Enables and runs the service.

## Manual Pull (Alternative)
If not using the systemd service, run pull-cert.sh manually:
   ```bash
   sudo /usr/local/bin/pull-cert.sh
   ```
   Output files:
   - `/etc/pki/tls/certs/example-cert.crt`
   - `/etc/pki/tls/private/example-key.key`

## Python Script (Alternative)
For Python-based applications:
```python
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
import base64
import logging

key_vault_uri = "https://example-vault.vault.azure.net/"
cert_name = "example-cert"
key_name = "example-key"
credential = ClientSecretCredential(
    tenant_id="tenant-id-uuid",
    client_id="client-id-uuid",
    client_secret="client-secret-base64"
)
secret_client = SecretClient(vault_url=key_vault_uri, credential=credential)

try:
    cert_secret = secret_client.get_secret(cert_name)
    key_secret = secret_client.get_secret(key_name)
    cert_pem = base64.b64decode(cert_secret.value)
    key_pem = base64.b64decode(key_secret.value)
    with open("/etc/pki/tls/certs/example-cert.crt", "wb") as f:
        f.write(cert_pem)
    with open("/etc/pki/tls/private/example-key.key", "wb") as f:
        f.write(key_pem)
    logging.info(f"Retrieved certificate: {cert_name} and key: {key_name}")
except Exception as e:
    logging.error(f"Failed to retrieve secrets: {str(e)}")
```

## Azure CLI (Alternative)
```bash
az keyvault secret show \
  --vault-name example-vault \
  --name example-cert \
  --query value \
  --output tsv | base64 -d > /etc/pki/tls/certs/example-cert.crt
az keyvault secret show \
  --vault-name example-vault \
  --name example-key \
  --query value \
  --output tsv | base64 -d > /etc/pki/tls/private/example-key.key
```

# Storing Credentials with Systemd and TPM
To securely store the service principal credentials (client-id-uuid, client-secret-base64, tenant-id-uuid), use systemd’s `LoadCredentialEncrypted` with TPM 2.0-backed encryption. This ensures credentials are encrypted at rest and only decrypted by the server’s TPM during service execution.

## Prerequisites
- **TPM 2.0:** Ensure the server has a TPM 2.0 chip and tools installed:
   ```bash
   sudo dnf install tpm2-tools tpm2-tss  # CentOS/Rocky
   ```
   Verify TPM:
   ```bash
   tpm2_getrandom 16
   ```
   
- **Systemd Version:** Requires systemd 252 or later for LoadCredentialEncrypted:
   ```bash
   systemctl --version
   ```
   
## Steps
1. **Prepare Credentials Directory:**
   ```bash
   sudo mkdir -p /etc/example-cert
   ```
   
2. **Encrypt Credentials with TPM:**
   Use `systemd-creds` to encrypt each credential:
   ```bash
   echo "client-id-uuid" | sudo systemd-creds encrypt --name=example-cert-client-id --with-key=tpm2 --tpm2-pcrs=0+7 - /etc/example-cert/example-cert-client-id
   echo "client-secret-base64" | sudo systemd-creds encrypt --name=example-cert-client-secret --with-key=tpm2 --tpm2-pcrs=0+7 - /etc/example-cert/example-cert-client-secret
   echo "tenant-id-uuid" | sudo systemd-creds encrypt --name=example-cert-tenant-id --with-key=tpm2 --tpm2-pcrs=0+7 - /etc/example-cert/example-cert-tenant-id
   ```
   - `--name`: Matches the credential ID in the service file.`
   - `--with-key=tpm2`: Binds encryption to the TPM.
   - `--tpm2-pcrs=0+7`: Locks firmware and Secure Boot state
   Output files are encrypted and stored in `/etc/example-cert/`.

   **Note on PCR Details**
   - **PCR 0:** Measures firmware (BIOS/UEFI) state. It changes only if the firmware is updated or reconfigured (e.g., BIOS update, Secure Boot toggle).
   
   - **PCR 7:** Measures Secure Boot state, including the Secure Boot policy, certificates, and the boot chain (e.g., shim, GRUB, kernel). It’s extended with measurements of each component loaded during boot.

3. Verify Service Configuration:
   The pull-cert.service (created by install-pull-cert.sh) already includes:
   ```ini
   LoadCredentialEncrypted=example-cert-client-id:/etc/example-cert/example-cert-client-id
   LoadCredentialEncrypted=example-cert-client-secret:/etc/example-cert/example-cert-client-secret
   LoadCredentialEncrypted=example-cert-tenant-id:/etc/example-cert/example-cert-tenant-id
   Environment="CREDENTIALS_DIRECTORY=/run/credentials/pull-cert.service"
   ```
   This loads the encrypted credentials into `/run/credentials/pull-cert.service` at runtime, decrypted by the TPM.

4. **Test Credential Loading:**
   Restart the service:
   ```bash
   sudo systemctl restart pull-cert.service
   ```
   
   Check logs:
   ```bash
   journalctl -u pull-cert.service -n 100
   ```
   
   Look for:
   ```
   Private key saved to /etc/pki/tls/private/example-key.key
   Certificate chain saved to /etc/pki/tls/certs/example-cert.crt
   ```
   
5. **Secure Directory:**
   ```bash
   sudo chmod 600 /etc/example-cert/*
   sudo chown root:root /etc/example-cert/*
   sudo chmod 700 /etc/example-cert
   ```
   
## Notes
 - **TPM Binding:** Credentials are tied to the server’s TPM, preventing use on other machines.
- **Backup:** Store unencrypted credentials securely elsewhere (e.g., encrypted vault) in case the TPM is reset.
- **Fallback:** If TPM is unavailable, use plain LoadCredential (less secure):
   ```ini
   LoadCredential=example-cert-client-id:/etc/example-cert/example-cert-client-id
   ```
   
# Scheduling
The pull-cert.service is a Type=oneshot service. To run it periodically (e.g., daily at 3 AM):
1. **Create a Timer:**
   ```bash
   sudo vi /etc/systemd/system/pull-cert.timer
   ```
   Content:
   ```ini
   [Unit]
   Description=Run pull-cert.service daily
   Requires=pull-cert.service
   
   [Timer]
   OnCalendar=daily
   Persistent=true
   RandomizedDelaySec=300
   
   [Install]
   WantedBy=timers.target
   ```
   
2. **Enable Timer:**
   ```bash
   sudo systemctl enable pull-cert.timer
   sudo systemctl start pull-cert.timer
   ```
   Verify:
   ```bash
   systemctl list-timers pull-cert.timer
   ```
Alternatively, use cron:
   ```bash
   sudo crontab -e
   ```
   Add:
   `0 3 * * * /usr/local/bin/pull-cert.sh >> /var/log/cert-pull.log 2>&1`

# Permissions
Ensure the server’s service principal has access to Key Vault:
- **Portal:**
   - Go to "Key Vaults" > `example-vault` > "Access control (IAM)" > "+ Add" > "Add role assignment".
   **Role:** "Key Vault Secrets User".
   **Assign access to:** Select "Service principal" > example-cert-puller (client-id-uuid).
   - Click "Review + assign".

- CLI:
   ```bash
   az role assignment create \
     --assignee client-id-uuid \
     --role "Key Vault Secrets User" \
     --scope "/subscriptions/subscription-id-uuid/resourceGroups/example-rg/providers/Microsoft.KeyVault/vaults/example-vault"
   ```
# Troubleshooting
- **Credential Errors:** Verify /etc/example-cert/ files are readable and TPM is functional:
   ```bash
   sudo systemd-creds decrypt /etc/example-cert/example-cert-client-id
   ```
- **Permission Denied:** Confirm "Key Vault Secrets User" role for client-id-uuid.
- **Service Fails:** Check logs:
   ```bash
   journalctl -u pull-cert.service -n 100
   ```
- **TPM Issues:** Ensure `tpm2-tss` and `tpm2-tools` are installed and TPM is enabled in BIOS.

# Maintenance
- **Credential Rotation:** Rotate client-secret-base64 periodically:
   ```bash
   az ad sp credential reset \
     --id client-id-uuid \
     --query password -o tsv
   ```
   Re-encrypt and update /etc/example-cert/example-cert-client-secret.
   
   - **File Permissions:** Regularly audit:
   ```bash
   ls -l /etc/pki/tls/private/example-key.key  # Should be 600, root:root
   ls -l /etc/pki/tls/certs/example-cert.crt   # Should be 644, root:root
   ```
