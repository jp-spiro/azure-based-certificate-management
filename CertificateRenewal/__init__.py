import logging
import json
import base64
import requests
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.mgmt.dns import DnsManagementClient
from azure.keyvault.secrets import SecretClient
from azure.keyvault.certificates import CertificateClient, CertificatePolicy

def sign_request(key, protected, payload):
    protected_b64 = base64.urlsafe_b64encode(json.dumps(protected, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip("=")
    signing_input = f"{protected_b64}.{payload_b64}".encode('utf-8')
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip("=")
    return {"protected": protected_b64, "payload": payload_b64, "signature": signature_b64}

def main(mytimer: func.TimerRequest) -> None:
    logging.info('Certificate renewal function triggered.')
    directory_url = "https://acme-v02.api.letsencrypt.org/directory"
    domain = "*.your-domain.com"
    dns_zone = "your-domain.com"
    resource_group = "your-group"
    subscription_id = "<your-subscription-id>"
    key_vault_uri = "https://your-domain-cert-vault.vault.azure.net/"

    credential = DefaultAzureCredential()
    dns_client = DnsManagementClient(credential, subscription_id)
    secret_client = SecretClient(vault_url=key_vault_uri, credential=credential)
    cert_client = CertificateClient(vault_url=key_vault_uri, credential=credential)

    # Account key for ACME operations
    account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    e_value = account_key.public_key().public_numbers().e
    e_bytes = e_value.to_bytes((e_value.bit_length() + 7) // 8, "big")
    jwk = {
        "e": base64.urlsafe_b64encode(e_bytes).decode('utf-8').rstrip("="),
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(account_key.public_key().public_numbers().n.to_bytes(256, "big")).decode('utf-8').rstrip("=")
    }
    jwk_canonical = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    logging.info(f"JWK: {jwk_canonical}")
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(jwk_canonical.encode('utf-8'))
    thumbprint = base64.urlsafe_b64encode(hasher.finalize()).decode('utf-8').rstrip("=")
    logging.info(f"Thumbprint: {thumbprint}")

    directory = requests.get(directory_url).json()

    # Register account
    nonce = requests.head(directory["newNonce"]).headers["Replay-Nonce"]
    jws = sign_request(account_key, {"alg": "RS256", "jwk": jwk, "nonce": nonce, "url": directory["newAccount"]},
                      {"contact": ["mailto:info@your-domain.com"], "termsOfServiceAgreed": True})
    reg_response = requests.post(directory["newAccount"], json=jws, headers={"Content-Type": "application/jose+json"})
    logging.info(f"Registration response: {reg_response.status_code} - {reg_response.text}")
    if reg_response.status_code not in (201, 200):
        logging.error(f"Failed to register account: {reg_response.text}")
        return
    account_url = reg_response.headers["Location"]

    # New order
    nonce = requests.head(directory["newNonce"]).headers["Replay-Nonce"]
    jws = sign_request(account_key, {"alg": "RS256", "kid": account_url, "nonce": nonce, "url": directory["newOrder"]},
                      {"identifiers": [{"type": "dns", "value": domain}]})
    order_response = requests.post(directory["newOrder"], json=jws, headers={"Content-Type": "application/jose+json"})
    logging.info(f"Order response: {order_response.status_code} - {order_response.text}")
    order = order_response.json()

    # DNS-01 challenge
    authz_url = order["authorizations"][0]
    authz_response = requests.get(authz_url)
    authz = authz_response.json()
    dns_challenge = next(c for c in authz["challenges"] if c["type"] == "dns-01")
    token = dns_challenge["token"]
    key_auth = f"{token}.{thumbprint}"
    logging.info(f"Key authorization: {key_auth}")
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(key_auth.encode('utf-8'))
    dns_token = base64.urlsafe_b64encode(hasher.finalize()).decode('utf-8').rstrip("=")
    logging.info(f"Setting TXT record for _acme-challenge.{dns_zone} to {dns_token}")

    # Set TXT record
    dns_client.record_sets.create_or_update(
        resource_group_name=resource_group,
        zone_name=dns_zone,
        relative_record_set_name="_acme-challenge",
        record_type="TXT",
        parameters={"ttl": 60, "txt_records": [{"value": [dns_token]}]}
    )
    logging.info("TXT record set—waiting 15s for propagation (confirmed fast).")
    time.sleep(15)

    # Respond to challenge
    challenge_url = dns_challenge["url"]
    nonce = requests.head(directory["newNonce"]).headers["Replay-Nonce"]
    jws = sign_request(account_key, {"alg": "RS256", "kid": account_url, "nonce": nonce, "url": challenge_url}, {})
    challenge_response = requests.post(challenge_url, json=jws, headers={"Content-Type": "application/jose+json"})
    logging.info(f"Challenge response: {challenge_response.status_code} - {challenge_response.text}")

    # Poll challenge status
    for _ in range(20):  # ~2 minutes
        challenge_check = requests.get(challenge_url).json()
        logging.info(f"Challenge status: {challenge_check['status']}")
        if challenge_check["status"] == "valid":
            break
        elif challenge_check["status"] == "invalid":
            logging.error(f"Challenge failed: {challenge_check.get('error', 'No error details')}")
            dns_client.record_sets.delete(resource_group, dns_zone, "_acme-challenge", "TXT")
            return
        time.sleep(6)

    if challenge_check["status"] != "valid":
        logging.error("Challenge not valid—cleaning up DNS.")
        dns_client.record_sets.delete(resource_group, dns_zone, "_acme-challenge", "TXT")
        return

    # Poll order status
    order_url = order_response.headers["Location"]
    for _ in range(10):  # ~1 minute
        order_check = requests.get(order_url).json()
        logging.info(f"Order status: {order_check['status']}")
        if order_check["status"] in ("ready", "valid"):
            break
        elif order_check["status"] == "invalid":
            logging.error("Order became invalid after valid challenge—check ACME.")
            dns_client.record_sets.delete(resource_group, dns_zone, "_acme-challenge", "TXT")
            return
        time.sleep(6)

    if order_check["status"] != "ready":
        logging.error("Order not ready—cleaning up DNS.")
        dns_client.record_sets.delete(resource_group, dns_zone, "_acme-challenge", "TXT")
        return

    # Generate a separate key for the CSR
    cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Finalize
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain)
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)]),
        critical=False
    ).sign(cert_key, hashes.SHA256())
    csr_der = base64.urlsafe_b64encode(csr.public_bytes(serialization.Encoding.DER)).decode('utf-8').rstrip("=")
    nonce = requests.head(directory["newNonce"]).headers["Replay-Nonce"]
    jws = sign_request(account_key, {"alg": "RS256", "kid": account_url, "nonce": nonce, "url": order["finalize"]},
                      {"csr": csr_der})
    finalize_response = requests.post(order["finalize"], json=jws, headers={"Content-Type": "application/jose+json"})
    logging.info(f"Finalize response: {finalize_response.status_code} - {finalize_response.text}")

    # Get cert
    if finalize_response.status_code == 200:
        cert_url = finalize_response.json().get("certificate")
        for _ in range(10):  # ~1 minute
            cert_response = requests.get(cert_url, headers={"Accept": "application/pem-certificate-chain"})
            if cert_response.status_code == 200:
                cert = cert_response.content
                break
            time.sleep(6)
        else:
            logging.error("Cert not ready after polling.")
            dns_client.record_sets.delete(resource_group, dns_zone, "_acme-challenge", "TXT")
            return
    else:
        logging.error("Finalization failed—no cert retrieved.")
        dns_client.record_sets.delete(resource_group, dns_zone, "_acme-challenge", "TXT")
        return

    # Convert private key to PEM
    private_key_pem = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Combine private key and certificate chain into a single PEM for certificate import
    combined_pem = private_key_pem + cert

    # Store private key as a secret and import combined PEM as a certificate
    try:
        secret_client.set_secret("your-domain-key", private_key_pem.decode('utf-8'))
        cert_client.import_certificate(
            certificate_name="your-domain-cert",
            certificate_bytes=combined_pem,  # Include both private key and certificate chain
            policy=CertificatePolicy(content_type="application/x-pem-file")
        )
        logging.info("Private key stored as secret and certificate chain imported to Key Vault.")
    except Exception as e:
        logging.error(f"Failed to upload to Key Vault: {str(e)}")
        dns_client.record_sets.delete(resource_group, dns_zone, "_acme-challenge", "TXT")
        raise

    # Clean up DNS
    dns_client.record_sets.delete(resource_group, dns_zone, "_acme-challenge", "TXT")
    logging.info("DNS TXT record cleaned up.")