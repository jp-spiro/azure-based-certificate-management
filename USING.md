# Certificate Management

This repository contains an Azure-based solution for automating the generation and renewal of Let's Encrypt wildcard certificates (`*.your-domain.com`) using the ACME protocol's DNS-01 challenge. The certificates and private keys are stored securely in Azure Key Vault as separate secrets (`your-domain-cert` and `your-domain-key`), and servers can pull them for use in TLS configurations. The solution leverages Azure Functions for scheduling, Azure DNS for challenge validation, and Azure Key Vault for storage, all without relying on external tools like Certbot.

## Overview

The solution automates the following:
- **Certificate Generation/Renewal**: An Azure Function (`CertificateRenewal`) runs on a timer to generate or renew a Let's Encrypt wildcard certificate (`*.your-domain.com`) using the ACME v2 API and DNS-01 challenge.
- **DNS Validation**: Updates TXT records in Azure DNS (`your-domain.com`) to validate domain ownership.
- **Certificate Storage**: Stores the certificate chain as a secret (`your-domain-cert`) and the private key as a separate secret (`your-domain-key`) in Azure Key Vault (`https://your-domain-vault.vault.azure.net/`).
- **Server Access**: Allows servers to pull the certificate and private key from Key Vault for use in applications (e.g., web servers).

This is a fully Azure-based, cloud-native solution with no local server dependencies, leveraging Azure Functions' free tier (up to 1 million executions/month) and minimal costs for Key Vault and DNS.

# Prerequisites

- **Azure Subscription:** Active subscription (ID: `subscription-id-uuid`)
- **Domain Ownership:** Control over `your-domain.com`
- **Azure Portal Access:** Permissions to create and manage resources in the `your-group` resource group
- **GitHub Account:** For hosting the repository at `https://github.com/your-domain-org/certificate-management`

# Setup

## Azure Resources (Portal Setup)

Below are step-by-step instructions to configure the required Azure resources using the Azure Portal, with `az` CLI commands provided as alternatives for automation or verification.

### 1. Azure DNS Zone

**Purpose**: Manages DNS records for `your-domain.com` to handle the DNS-01 challenge by updating TXT records.

**Portal Setup**:
1. **Navigate**: Log in to the [Azure Portal](https://portal.azure.com) > Search for "DNS Zones" in the top search bar > Select "DNS Zones".
2. **Create DNS Zone**:
   - Click "+ Create".
   - **Subscription**: Select your subscription (`subscription-id-uuid`).
   - **Resource Group**: Choose `your-group` (or create it if it doesn’t exist: click "Create new", enter `your-group`, and click "OK").
   - **Name**: Enter `your-domain.com`.
   - **Region**: Leave as default (global resource).
   - Click "Review + create" > "Create".
3. **Get Nameservers**:
   - Once created, go to "DNS Zones" > `your-domain.com` > "Overview".
   - Note the four nameservers listed (e.g., `ns1-01.azure-dns.com`, `ns2-01.azure-dns.net`, etc.).
4. **Update Domain Registrar**:
   - Log in to your domain registrar (e.g., GoDaddy, Namecheap).
   - Update the nameservers for `your-domain.com` to match the Azure DNS nameservers from the previous step.
   - Allow 24-48 hours for DNS propagation.

**CLI Alternative**:
```bash
# Create DNS Zone
az network dns zone create \
  --resource-group your-domain \
  --name your-domain.com \
  --subscription <subscription-id-uuid>

# Get Nameservers
az network dns zone show \
  --resource-group your-domain \
  --name your-domain.com \
  --query nameServers -o tsv
```

**Test:**
- Verify DNS resolution:
```bash
nslookup -type=NS your-domain.com
```
Ensure it returns Azure’s nameservers.

### 2. Azure Key Vault

**Purpose:** Stores the generated certificate (your-domain-cert) securely.

**Portal Setup:**
1.	**Navigate:** Search for "Key Vaults" in the top search bar > Select "Key Vaults".
2.	**Create Key Vault:**
    - Click "+ Create".
    - Subscription: Select `<subscription-id-uuid>`.
    - Resource Group: Choose `<your-group>`.
    - Key Vault Name: Enter `your-domain-cert-vault`.
    - Region: Select a region (e.g., East US).
    - Leave other settings as default (e.g., Standard pricing tier).
    - Click "Review + create" > "Create".
3.	**Note URI:**
    - Once created, go to "Key Vaults" > your-domain-cert-vault > "Overview".
    - Copy the "Vault URI" (e.g., https://your-domain-cert-vault.vault.azure.net/).

**CLI Alternative:**
```bash
# Create Key Vault
az keyvault create \
  --name your-domain-cert-vault \
  --resource-group your-group \
  --location eastus \
  --subscription <subscription-id-uuid>

# Get URI
az keyvault show \
  --name your-domain-cert-vault \
  --resource-group your-group \
  --query properties.vaultUri -o tsv
```

**Test:**
- Verify Key Vault exists:
```bash
az keyvault show \
  --name your-domain-cert-vault \
  --resource-group your-group \
  --query name -o tsv
```
Expected output: `your-domain-cert-vault`.

### 3. Azure Function App

**Purpose:** Hosts the CertificateRenewal function to automate certificate generation.

**Portal Setup:**
1.	Navigate: Search for "Function App" in the top search bar > Select "Function App".
2.	Create Function App:
    - Click "+ Create".
    - Subscription: Select `<subscription-id-uuid>`.
    - Resource Group: Choose `your-domain`.
    - Function App name: Enter `your-domain-certificate-management` (unique across Azure).
    - Publish: Select "Code".
    - Runtime stack: Choose "Python".
    - Version: Select "3.11".
    - Region: Select a region (e.g., East US).
    - Click "Next: Hosting".
3.	Hosting:
    - Storage account: Use an existing one or create a new one (e.g., `your-domainstorage).
    - Operating System: Select "Linux".
    - Plan type: Choose "Flex Consumption" (cost-effective, replaces Consumption plan in some regions).
    - Click "Review + create" > "Create".
4.	Enable Managed Identity:
    - Once created, go to "Function App" > `your-domain-certificate-management` > "Identity" (left menu).
    - Under "System assigned", toggle "Status" to "On".
    - Click "Save" > "Yes" to confirm.
    - Note the "Object (principal) ID" (e.g., `<principal-id-uuid>`).

**CLI Alternative:**
```bash
# Create Storage Account (if needed)
az storage account create \
  --name your-domainstorage \
  --resource-group your-domain \
  --location eastus \
  --sku Standard_LRS \
  --subscription <subscription-id-uuid>

# Create Function App
az functionapp create \
  --name your-domain-certificate-management \
  --resource-group your-domain \
  --storage-account your-domainstorage \
  --runtime python \
  --runtime-version 3.11 \
  --os-type linux \
  --consumption-plan-location eastus \
  --subscription <subscription-id-uuid>

# Enable System-Assigned Managed Identity
az functionapp identity assign \
  --name your-domain-certificate-management \
  --resource-group your-domain \
  --query principalId -o tsv
```

**Test:**
- Verify Function App exists and identity is enabled:

```bash
az functionapp show \
  --name your-domain-certificate-management \
  --resource-group your-domain \
  --query name -o tsv
az functionapp identity show \
  --name your-domain-certificate-management \
  --resource-group your-domain \
  --query principalId -o tsv
```

### 4. Permissions

**Purpose:** Grants the Function App’s managed identity access to Azure DNS and Key Vault.

**Portal Setup:**
1.	Key Vault Permission:
    - Go to "Key Vaults" > your-domain-cert-vault > "Access control (IAM)" (left menu).
    - Click "+ Add" > "Add role assignment".
    - Role: Search for and select "Key Vault Certificates Officer".
    - Click "Next".
    - Assign access to: Select "Managed identity".
    - Click "+ Select members".
    - Subscription: <subscription-id-uuid>.
    - Managed identity: Select "Function App" > your-domain-certificate-management (Principal ID: <principal-id-uuid>).
    - Click "Select" > "Next" > "Review + assign".
2.	DNS Zone Permission:
    - Go to "DNS Zones" > your-domain.com > "Access control (IAM)" (left menu).
    - Click "+ Add" > "Add role assignment".
    - Role: Search for and select "DNS Zone Contributor".
    - Click "Next".
    - Assign access to: Select "Managed identity".
    - Click "+ Select members".
    - Subscription: <subscription-id-uuid>.
    - Managed identity: Select "Function App" > your-domain-certificate-management.
    - Click "Select" > "Next" > "Review + assign".
3.	Verify Permissions:
    - For Key Vault: Go to your-domain-cert-vault > "Access control (IAM)" > "View my access" > Search for <principal-id-uuid> to confirm "Key Vault Certificates Officer".
    - For DNS Zone: Go to your-domain.com > "Access control (IAM)" > "View my access" > Confirm "DNS Zone Contributor".

**CLI Alternative:**
```bash
# Assign Key Vault permission
az role assignment create \
  --assignee <principal-id-uuid> \
  --role "Key Vault Certificates Officer" \
  --scope "/subscriptions/<subscription-id-uuid>/resourceGroups/your-domain/providers/Microsoft.KeyVault/vaults/your-domain-cert-vault"

# Assign DNS Zone permission
az role assignment create \
  --assignee <principal-id-uuid> \
  --role "DNS Zone Contributor" \
  --scope "/subscriptions/<subscription-id-uuid>/resourceGroups/your-domain/providers/Microsoft.Network/dnsZones/your-domain.com"

# Verify permissions
az role assignment list \
  --assignee <principal-id-uuid> \
  --scope "/subscriptions/<subscription-id-uuid>/resourceGroups/your-domain/providers/Microsoft.KeyVault/vaults/your-domain-cert-vault" \
  --query "[?roleDefinitionName=='Key Vault Certificates Officer'].roleDefinitionName" -o tsv
# Expected: Key Vault Certificates Officer

az role assignment list \
  --assignee <principal-id-uuid> \
  --scope "/subscriptions/<subscription-id-uuid>/resourceGroups/your-domain/providers/Microsoft.Network/dnsZones/your-domain.com" \
  --query "[?roleDefinitionName=='DNS Zone Contributor'].roleDefinitionName" -o tsv
# Expected: DNS Zone Contributor
```

## Repository Structure
The repository (`https://github.com/your-domain/certificate-management`) contains:
```
certificate-management/
├── CertificateRenewal/
│   ├── __init__.py       # Azure Function code
│   ├── function.json     # Timer trigger configuration
├── requirements.txt      # Python dependencies
└── .github/workflows/main_your-domain-certificate-management.yml  # GitHub Actions workflow
```

### Function Code (CertificateRenewal/init.py)
See the correct code you provided earlier (#) for the full implementation. Key features:
- Generates a JWK with ordered keys (e, kty, n) for thumbprint calculation.
- Uses a separate certificate key from the account key.
- Updates Azure DNS with TXT records for DNS-01 validation.
- Stores the certificate as a PEM file in Key Vault.
- Cleans up DNS records post-execution.

### Timer Trigger (CertificateRenewal/function.json)
```json
{
  "scriptFile": "__init__.py",
  "bindings": [
    {
      "name": "mytimer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "0 0 2 * * 1"
    }
  ]
}
```

### Dependencies (requirements.txt)
```
azure-functions
azure-identity
azure-keyvault-certificates
azure-mgmt-dns
cryptography>=43.0.0
requests
```

### GitHub Actions Workflow (.github/workflows/main_your-domain-certificate-management.yml)
See the workflow for the full YAML. It builds and deploys the function to your-domain-certificate-management.

# Deployment
1.	Clone the Repository:
```bash
git clone https://github.com/jp-spiro/certificate-management.git
cd certificate-management
```

2.	Update Email:
    - Open `CertificateRenewal/__init__.py`.
    - Replace `info@your-domain.com` with your email.
3.	Commit and Push:
```bash
git add .
git commit -m "Configure CertificateRenewal function"
git push origin main
```

GitHub Actions deploys to `your-domain-certificate-management.azurewebsites.net`.
4.	Verify Deployment:
    - Azure Portal > "Function App" > `your-domain-certificate-management` > "Functions".
    - Confirm `CertificateRenewal` is listed.

# Testing
1.	Manual Trigger:
    - Azure Portal > `your-domain-certificate-management` > "Functions" > `CertificateRenewal` > "Code + Test".
    - Click "Test/Run" > "Run".
    - Check logs (bottom pane or "Monitor" tab) for:
        - `Certificate renewal function triggered`
        - `Setting TXT record for _acme-challenge.your-domain.com`
        - `Challenge status: valid`
        - `Certificate renewed and uploaded to Key Vault as PEM`
        - `DNS TXT record cleaned up`
2.	Verify Key Vault:
    - Azure Portal > "Key Vaults" > `your-domain-cert-vault` > "Certificates" > `your-domain-cert`.
    - Or CLI:

```bash
az keyvault secret show \
  --vault-name your-domain-cert-vault \
  --name your-domain-cert \
  --query value \
  --output tsv | base64 -d > your-domain-cert.pem
openssl x509 -in your-domain-cert.pem -text -noout
```
# Pulling Certificates to Servers

## Generate Secrets
```bash
az ad sp create-for-rbac   --name "your-domain-cert-puller"   --role "Key Vault Secrets User"   --scopes "/subscriptions/<subscription-id-uuid>/resourceGroups/your-domain/providers/Microsoft.KeyVault/vaults/your-domain-cert-vault"

Creating 'Key Vault Secrets User' role assignment under scope '/subscriptions/<subscription-id-uuid>/resourceGroups/your-domain/providers/Microsoft.KeyVault/vaults/your-domain-cert-vault'
The output includes credentials that you must protect. Be sure that you do not include these credentials in your code or check the credentials into your source control. For more information, see https://aka.ms/azadsp-cli
{
  "appId": "<your-app-id>",
  "displayName": "your-domain-cert-puller",
  "password": "<your-password>",
  "tenant": "<your-tenant-id>"
}

## Python Script
```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
import base64
import logging

key_vault_uri = "https://your-domain-cert-vault.vault.azure.net/"
cert_name = "your-domain-cert"

credential = DefaultAzureCredential()
cert_client = CertificateClient(vault_url=key_vault_uri, credential=credential)

try:
    secret = cert_client.get_secret(cert_name)
    cert_pem = base64.b64decode(secret.value)
    with open("/path/to/your-domain-cert.pem", "wb") as f:
        f.write(cert_pem)
    logging.info(f"Retrieved certificate: {cert_name}")
except Exception as e:
    logging.error(f"Failed to retrieve certificate: {str(e)}")
```    

## Azure CLI
```bash
az keyvault secret show \
  --vault-name your-domain-cert-vault \
  --name your-domain-cert \
  --query value \
  --output tsv | base64 -d > /path/to/your-domain-cert.pem
```

## Permissions
- Azure Portal > "Key Vaults" > `your-domain-cert-vault` > "Access control (IAM)" > "+ Add" > "Add role assignment".
- **Role:** "Key Vault Certificates User".
- **Assign access to:** "Managed identity" (or service principal for non-Azure servers).
- **Select:** Server’s identity > "Review + assign".

## Scheduling
```bash
0 3 * * * /path/to/pull-cert.sh >> /var/log/cert-pull.log 2>&1
```

# Cost Considerations
- Azure Functions: Free tier (1 million executions/month) for weekly runs.
- Azure Key Vault: ~$0.03 per 10,000 operations.
- Azure DNS: ~$0.50 per hosted zone/month + query costs.

# Troubleshooting
- Function Fails: Check logs in "Monitor" tab for errors (e.g., DNS or Key Vault access issues).
- Certificate Missing: Verify upload in Key Vault via Portal or CLI.
- Server Pull Fails: Confirm server identity permissions in Key Vault IAM.

# Maintenance
- Renewal: Runs weekly, renews before 90-day expiry (e.g., July 9, 2025).
- Monitoring: Use Azure Application Insights or Function logs.
- Updates: Keep cryptography>=43.0.0 current.
Contributing
1.	Fork the repo.
2.	Create a branch (git checkout -b feature/xyz).
3.	Commit (git commit -m "Add xyz").
4.	Push (git push origin feature/xyz).
5.	Open a Pull Request.
