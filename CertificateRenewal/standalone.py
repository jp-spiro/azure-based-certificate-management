import json
import base64
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def main():
    print("Certificate renewal simulation started.")
    directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
    domain = "*.your-domain.com"

    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(key.public_key().public_numbers().n.to_bytes(256, "big")).decode('utf-8').rstrip("="),
        "e": base64.urlsafe_b64encode(key.public_key().public_numbers().e.to_bytes(4, "big")).decode('utf-8').rstrip("=")
    }
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(json.dumps(jwk, separators=(',', ':')).encode('utf-8'))
    thumbprint = base64.urlsafe_b64encode(hasher.finalize()).decode('utf-8').rstrip("=")

    # Get ACME directory
    directory = requests.get(directory_url).json()

    # Register account
    reg_payload = {"contact": ["mailto:info@your-domain.com"], "termsOfServiceAgreed": True}
    nonce = requests.head(directory["newNonce"]).headers["Replay-Nonce"]
    print(f"Fetched nonce: {nonce}")
    protected = {"alg": "RS256", "jwk": jwk, "nonce": nonce, "url": directory["newAccount"]}
    protected_b64 = base64.urlsafe_b64encode(json.dumps(protected, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(reg_payload, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip("=")
    signing_input = f"{protected_b64}.{payload}".encode('utf-8')
    print(f"Signing input (hex): {signing_input.hex()}")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip("=")
    jws = {"protected": protected_b64, "payload": payload, "signature": signature_b64}
    try:
        key.public_key().verify(base64.urlsafe_b64decode(signature_b64 + "=="), signing_input, padding.PKCS1v15(), hashes.SHA256())
        print("Local signature verification passed!")
    except Exception as e:
        print(f"Local signature verification failed: {e}")
        return

    print(f"Raw JWS for registration: {json.dumps(jws)}")
    reg_response = requests.post(
        directory["newAccount"],
        json=jws,
        headers={"Content-Type": "application/jose+json"}
    )
    print(f"Registration response: {reg_response.status_code} - {reg_response.text}")
    if reg_response.status_code not in (201, 200):
        print("Registration failed!")
        return
    account_url = reg_response.headers["Location"]

    # New order
    order_payload = {"identifiers": [{"type": "dns", "value": domain}]}
    nonce = requests.head(directory["newNonce"]).headers["Replay-Nonce"]
    protected = {"alg": "RS256", "kid": account_url, "nonce": nonce, "url": directory["newOrder"]}
    protected_b64 = base64.urlsafe_b64encode(json.dumps(protected, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(order_payload, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip("=")
    signing_input = f"{protected_b64}.{payload}".encode('utf-8')
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip("=")
    jws = {"protected": protected_b64, "payload": payload, "signature": signature_b64}
    order_response = requests.post(
        directory["newOrder"],
        json=jws,
        headers={"Content-Type": "application/jose+json"}
    )
    print(f"Order response: {order_response.status_code} - {order_response.text}")
    order = order_response.json()

    # DNS-01 challenge prep
    for authz_url in order["authorizations"]:
        authz_response = requests.get(authz_url)
        authz = authz_response.json()
        dns_challenge = next(c for c in authz["challenges"] if c["type"] == "dns-01")
        token = dns_challenge["token"]
        key_auth = f"{token}.{thumbprint}"
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(key_auth.encode('utf-8'))
        dns_token = base64.urlsafe_b64encode(hasher.finalize()).decode('utf-8').rstrip("=")
        print(f"DNS-01 challenge: Set TXT record for _acme-challenge.{domain} to {dns_token}")

if __name__ == "__main__":
    main()