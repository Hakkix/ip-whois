# Regenerates the TLS test fixtures. Test-only keys and a private test CA;
# nothing here is trusted by production code. Run: python3 generate.py
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

def dt(y): return datetime(y, 1, 1, tzinfo=timezone.utc)
def name(cn, org="ip-whois test"): return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def pem(c): return c.public_bytes(serialization.Encoding.PEM)
def key_pem(k): return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
def write(n, data): open(n, "wb").write(data)

def build(subject, issuer, pub, signer, nb, na, ca=False, sans=None, path_len=None):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True))
    if sans: b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return b.sign(signer, hashes.SHA256())

ca_key = ec.generate_private_key(ec.SECP256R1())
ca = build(name("Test Root CA"), name("Test Root CA"), ca_key.public_key(), ca_key, dt(2020), dt(2120), ca=True)
int_key = ec.generate_private_key(ec.SECP256R1())
inter = build(name("Test Intermediate CA"), ca.subject, int_key.public_key(), ca_key, dt(2020), dt(2120), ca=True, path_len=0)
write("ca.pem", pem(ca)); write("intermediate.pem", pem(inter))

def leaf(tag, cn, sans, nb, na, key=None, signer=inter, signer_key=int_key):
    k = key or rsa.generate_private_key(65537, 2048)
    c = build(name(cn), signer.subject, k.public_key(), signer_key, nb, na, sans=sans)
    write(f"{tag}.key.pem", key_pem(k)); write(f"{tag}.pem", pem(c))

leaf("valid", "valid.test-host.com", ["valid.test-host.com", "*.wild.test-host.com"], dt(2020), dt(2120))
leaf("expired", "valid.test-host.com", ["valid.test-host.com"], dt(2015), dt(2016))
leaf("wronghost", "other.test-host.com", ["other.test-host.com"], dt(2020), dt(2120))
leaf("ecdsa", "valid.test-host.com", ["valid.test-host.com"], dt(2020), dt(2120), key=ec.generate_private_key(ec.SECP384R1()))
# self-signed leaf
k = rsa.generate_private_key(65537, 2048)
c = build(name("valid.test-host.com"), name("valid.test-host.com"), k.public_key(), k, dt(2020), dt(2120), sans=["valid.test-host.com"])
write("selfsigned.key.pem", key_pem(k)); write("selfsigned.pem", pem(c))
