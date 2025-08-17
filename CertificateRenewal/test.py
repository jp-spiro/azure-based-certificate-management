import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
jwk = {
    "kty": "RSA",
    "n": base64.urlsafe_b64encode(key.public_key().public_numbers().n.to_bytes(256, "big")).decode('utf-8'),
    "e": base64.urlsafe_b64encode(key.public_key().public_numbers().e.to_bytes(4, "big")).decode('utf-8')
}
protected = {"alg": "RS256", "jwk": jwk, "nonce": "6Oat0CnA6xGc2aGNZtiMu-VmFLtrC52l0pdiHhuCKHNrwaba0_w", "url": "https://acme-v02.api.letsencrypt.org/acme/new-acct"}
protected_b64 = base64.urlsafe_b64encode(json.dumps(protected, separators=(',', ':')).encode('utf-8')).decode('utf-8')
payload = base64.urlsafe_b64encode(json.dumps({"contact": ["mailto:info@your-domain.com"], "termsOfServiceAgreed": True}, separators=(',', ':')).encode('utf-8')).decode('utf-8')
signing_input = f"{protected_b64}.{payload}".encode('utf-8')
signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8')
key.public_key().verify(base64.urlsafe_b64decode(signature_b64), signing_input, padding.PKCS1v15(), hashes.SHA256())
print("Regenerated signature is valid!")