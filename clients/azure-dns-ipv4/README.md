# Azure DNS: dynamic public IPv4 (A record)

`azure-dns-update-a.sh` discovers this machine's **public egress IPv4** (using HTTPS `curl -4`, so it works for a normal Linux host behind NAT that is not the router) and upserts an **A** record in **Azure DNS** via the Azure Resource Manager API.

The same script runs on **pfSense** (FreeBSD) or **Linux**; it only needs **curl** (no `jq`).

**You do not edit the script** for your zone or file layout: pass **flags** or **environment variables** (see `-h` / `--help`).

## Azure setup

1. Use the same public DNS zone you already host on Azure (or create one).
2. Create a **separate** app registration for DNS updates (recommended), or reuse an existing service principal.
3. Grant that principal **DNS Zone Contributor** on the DNS zone (or the resource group containing it). This is a different scope than Key Vault Secrets User.

### Where is the subscription ID?

It is **not** the same as tenant ID or app (client) ID. The subscription ID is the GUID of the **Azure subscription** that owns your DNS zone (and Key Vault, Function App, etc.).

Find it in the **Azure Portal** under **Subscriptions** (copy the **Subscription ID** column), or with the CLI:

```bash
az account show --query id -o tsv
```

The original certificate automation only hardcodes it as a placeholder in `CertificateRenewal/__init__.py` (`<your-subscription-id>`). The Linux Key Vault pull scripts **do not** store the subscription ID; ARM calls for DNS need it explicitly.

You can pass **`-S` / `--subscription`**, set **`AZURE_SUBSCRIPTION_ID`** in the environment, put the GUID in a file pointed to by **`AZURE_SUBSCRIPTION_ID_FILE`**, or add a one-line file next to your SP credentials (see below).

## Required settings

| Flag (short) | Long form | Environment variable | Meaning |
|----------------|-----------|----------------------|---------|
| `-z` | `--zone` | `AZURE_DNS_ZONE` | Root zone (e.g. `example.com`) |
| `-n` | `--record` | `AZURE_DNS_RECORD_NAME` | Relative A name (e.g. `home`, `dyn`) or `@` for apex |
| `-g` | `--resource-group` | `AZURE_RESOURCE_GROUP` | Resource group that contains the zone |
| `-S` | `--subscription` | `AZURE_SUBSCRIPTION_ID` | Subscription ID |

Flags override environment if both are set.

## Service principal credentials (pick one)

### 1) Directory + filename prefix (typical on a server)

Files:

- `${CREDENTIALS_DIRECTORY}/${CREDENTIAL_FILE_PREFIX}-client-id`
- `${CREDENTIALS_DIRECTORY}/${CREDENTIAL_FILE_PREFIX}-client-secret`
- `${CREDENTIALS_DIRECTORY}/${CREDENTIAL_FILE_PREFIX}-tenant-id`

Each file may be either **one line of plain text** (UUID, secret, RG name) or the same **systemd-creds–encrypted** format you store under `/etc/...` for TPM. The script runs **`systemd-creds decrypt`** on each path when that succeeds, otherwise it reads the file as plaintext. You need **`systemd-creds`** on `PATH` and a TPM session where decrypt works (often: run as **root** on the same machine that encrypted the files). For **cron** without a TPM context, prefer a **systemd timer** with `LoadCredentialEncrypted` and `CREDENTIALS_DIRECTORY=/run/credentials/…` so decrypted values are supplied automatically.

| Flag | Environment |
|------|-------------|
| `-d DIR` | `CREDENTIALS_DIRECTORY` |
| `-p PREFIX` | `CREDENTIAL_FILE_PREFIX` |

If you use `-d` / `CREDENTIALS_DIRECTORY`, you **must** also set `-p` / `CREDENTIAL_FILE_PREFIX`.

**Optional** one-line text files in the same directory (only used if you do **not** pass `-S` / `-g` or set `AZURE_SUBSCRIPTION_ID` / `AZURE_RESOURCE_GROUP` already):

- `${CREDENTIAL_FILE_PREFIX}-subscription-id` — Azure subscription GUID
- `${CREDENTIAL_FILE_PREFIX}-resource-group` — name of the resource group that contains the DNS zone

With prefix `my-dns-sp`, add optional one-line files `my-dns-sp-subscription-id` and `my-dns-sp-resource-group` next to `my-dns-sp-client-id`, then you can omit `-g` and `-S`.

**Example:** credentials under `/etc/mycerts` with prefix `my-dns-sp`:

```sh
./azure-dns-update-a.sh \
  --zone=example.com \
  --record=home \
  --resource-group=my-rg \
  --subscription="$AZURE_SUBSCRIPTION_ID" \
  --credentials-dir=/etc/mycerts \
  --credential-prefix=my-dns-sp
```

With **`my-dns-sp-subscription-id`** and **`my-dns-sp-resource-group`** in `/etc/mycerts`, omit `-g` and `-S`:

```sh
./azure-dns-update-a.sh -z example.com -n dyn -d /etc/mycerts -p my-dns-sp
```

Short form with subscription and RG on the command line:

```sh
./azure-dns-update-a.sh -z example.com -n home -g my-rg -S "$AZURE_SUBSCRIPTION_ID" \
  -d /etc/mycerts -p my-dns-sp
```

### 2) Inline environment variables

Set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` (no files).

### 3) Explicit file paths

Set all of:

- `AZURE_CLIENT_ID_FILE`
- `AZURE_CLIENT_SECRET_FILE`
- `AZURE_TENANT_ID_FILE`

(full paths). This wins over directory + prefix if set.

**Precedence:** explicit `*_FILE` variables → directory + prefix → inline `AZURE_*` secrets.

## Optional

| Flag | Environment | Default |
|------|-------------|---------|
| `-t` / `--ttl` | `AZURE_DNS_TTL` | `300` |

`IPV4_DISCOVERY_URLS`: space-separated URLs that return a plain-text IPv4 address (override discovery).

**`-D` / `--debug` / `DEBUG_AZURE_DNS=1`:** prints extra context to stderr (token URL, subscription/RG hints, redacted AAD/ARM JSON). Secrets are not printed in full: only **length** for `client_secret`, **truncated UUIDs** for tenant/client/subscription, and **redacted** token fields in JSON snapshots.

## pfSense: install, credentials, TPM check, and test

pfSense is **FreeBSD** (no **systemd**, no **`systemd-creds`**). Credential files created with **TPM-backed encryption on Linux** cannot be decrypted on the router; use **separate, plain one-line files** on pfSense with strict permissions (or another encryption layer you manage yourself, e.g. GELI).

### 1) Install dependencies

SSH or **Diagnostics > Command Prompt** as root:

```sh
pkg install -y curl
```

The script uses `sh`, `curl`, `mktemp`, `grep`, `sed`, `tr`, `cut` (all present or pulled in with the base system once `curl` is installed).

### 2) Install the script

pfSense does **not** create **`/root/bin`** for you; create it once, then keep scripts there:

```sh
mkdir -p /root/bin
```

Copy `azure-dns-update-a.sh` to **`/root/bin/azure-dns-update-a.sh`**, then:

```sh
chmod 700 /root/bin/azure-dns-update-a.sh
```

If you skip `bin`, you can use **`/root/azure-dns-update-a.sh`** instead—the examples below assume **`/root/bin/`** for the script only; credentials stay under **`/root/azure-dns-creds`** (or another directory you choose).

### 3) Credentials (secure enough for most home labs)

1. Create a root-only directory, e.g. **`/root/azure-dns-creds`**, mode **700**:
   ```sh
   mkdir -p /root/azure-dns-creds
   chmod 700 /root/azure-dns-creds
   ```
2. Create **five** one-line text files (no trailing spaces; use the same `PREFIX` you pass as `-p`). Example prefix `my-dns-sp`:
   - `my-dns-sp-client-id` — application (client) ID GUID  
   - `my-dns-sp-client-secret` — current client secret value  
   - `my-dns-sp-tenant-id` — directory (tenant) ID GUID  
   - `my-dns-sp-subscription-id` — subscription GUID (optional if you pass `-S`)  
   - `my-dns-sp-resource-group` — resource group name (optional if you pass `-g`)  
3. Set ownership and mode:
   ```sh
   chmod 600 /root/azure-dns-creds/*
   chown root:wheel /root/azure-dns-creds/*
   ```

**Why not TPM on pfSense for this script:** even if hardware has a TPM, pfSense does not ship the **systemd + TPM credential** stack this repo uses on Linux. The script will still run: `read_secret_line` falls back to reading **plaintext** when `systemd-creds` is missing.

**Stronger options (optional):** store files on an **encrypted** ZFS dataset or **GELI** volume; or run updates from an internal Linux host instead of the router.

### 4) Check for TPM (informational)

From a root shell:

```sh
dmesg -a 2>/dev/null | grep -iE 'tpm|txt' | tail -20
pciconf -lv 2>/dev/null | grep -iE 'tpm|trusted'
```

If these show nothing relevant, treat the box as **no usable TPM for this workflow**. Many appliances have no TPM, or it is not exposed to FreeBSD the way Windows/Linux desktop stacks expect.

### 5) Test once

Use your real zone name, record label, prefix, and paths:

```sh
/root/bin/azure-dns-update-a.sh \
  -z example.com \
  -n dyn \
  -d /root/azure-dns-creds \
  -p my-dns-sp \
  -D
```

`-D` adds redacted diagnostics on stderr. Confirm **HTTP 200/201** on the DNS step, then verify the **A** record in Azure Portal.

### 6) Schedule (cron)

**System > Advanced > Cron** (or **System > Cron** depending on version): run as **root**, interval e.g. every 15–30 minutes or daily, **Command** the same line as above **without** `-D` once stable.

Alternatively put the `export` / flags in **`/usr/local/bin/azure-dns-update-run.sh`** (mode **700**), and call that single path from cron.

---

## Scheduling (Linux and summary)

- **Linux:** export variables or call the script with the same flags from cron/systemd (TPM + `systemd-creds` optional; see `clients/README.md`).
- **pfSense:** use **Cron** as in §6 above; credentials live under **`/root/...`** with **700/600** permissions unless you add full-disk or dataset encryption.

## IPv4 only

Discovery uses `curl -4` and only accepts an address matching a simple IPv4 pattern. IPv6 is intentionally out of scope here.
