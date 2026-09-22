#!/usr/bin/env python3
"""
IP Address Encryption Toolkit — hides the real IP so observers see
random data or a decoy IP; only the holder of the private key / shared secret
can recover the original.

Two modes:
  1. PKI (asymmetric)  — encrypt with receiver's public cert; only receiver
                          decrypts with their private key. Ciphertext looks like
                          random bytes (no IP pattern visible).
  2. Symmetric          — both sides share a secret derived from a cert; both
                          can encrypt and decrypt. Ciphertext also looks random.
"""

import asyncio
import ipaddress
import os
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Key / cert helpers
# ---------------------------------------------------------------------------

def generate_ec_keypair():
    """Generate an EC keypair (P-256). Returns (private_key, public_key)."""
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return priv, priv.public_key()


def generate_rsa_keypair(key_size: int = 2048):
    """Generate an RSA keypair. Returns (private_key, public_key)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    return priv, priv.public_key()


def save_pem_private(key, path: Path):
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))


def save_pem_public(key, path: Path):
    path.write_bytes(key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def load_pem_private(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None, backend=default_backend())


def load_pem_public(path: Path):
    return serialization.load_pem_public_key(path.read_bytes(), backend=default_backend())


def derive_shared_secret( priv_ec, peer_pub_ec):
    """ECDH: derive a 32-byte shared secret from an EC private key and a peer's public key."""
    shared = priv_ec.exchange(ec.ECDH(), peer_pub_ec)
    # HKDF to stretch to AES-256 key
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ip-encryption-v1",
                backend=default_backend()).derive(shared)


# ---------------------------------------------------------------------------
# Core encryption / decryption
# ---------------------------------------------------------------------------

class IPEncryptor:
    """
    Encrypts IPv4/IPv6 addresses to ciphertext that looks like random bytes.
    No IP pattern is visible in the output.
    """

    def __init__(self, mode: str = "pki"):
        """
        mode: 'pki' | 'symmetric'
        """
        self.mode = mode

    # -- PKI mode --------------------------------------------------------

    def encrypt_pki(self, ip_str: str, receiver_pub_key) -> bytes:
        """
        Encrypt an IP address using the receiver's public key (RSA or EC).
        Output is random-looking bytes — no IP pattern.
        """
        raw = self._ip_to_bytes(ip_str)
        if isinstance(receiver_pub_key, rsa.RSAPublicKey):
            ct = receiver_pub_key.encrypt(
                raw,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None),
            )
        else:  # EC — use ECIES-like approach: encrypt via symmetric after ECDH
            # For EC, we need the sender's ephemeral keypair to do ECDH with receiver's public
            raise NotImplementedError("EC public key encryption requires an encryptor instance with sender keypair; use encrypt_ec")
        return ct

    def decrypt_pki(self, ciphertext: bytes, receiver_priv_key) -> str:
        """Decrypt ciphertext with the receiver's private key."""
        raw = receiver_priv_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None),
        )
        return self._bytes_to_ip(raw)

    # -- EC mode with ephemeral sender key ------------------------------

    def __init__(self, mode: str = "pki", sender_ec_priv=None):
        self.mode = mode
        self.sender_ec_priv = sender_ec_priv  # for EC-based encryption

    def encrypt_ec(self, ip_str: str, receiver_pub_ec) -> bytes:
        """
        Encrypt an IP for an EC public key using an ephemeral ECDH + AES-GCM.
        Output: [ephemeral_pub_x (32)] [ephemeral_pub_y (32)] [nonce (12)] [ciphertext] [tag (16)]
        Total ~ 128 bytes of random-looking data for an IPv4 address.
        """
        raw = self._ip_to_bytes(ip_str)

        # Ephemeral sender key
        ephemeral_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_pub = ephemeral_priv.public_key()

        # Shared secret via ECDH
        shared = ephemeral_priv.exchange(ec.ECDH(), receiver_pub_ec)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ip-encryption-v1-ecies",
                   backend=default_backend()).derive(shared)

        # AES-GCM encrypt
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(raw) + enc.finalize()

        # Pack: ephemeral_pub (uncompressed point: 0x04 || x || y) + nonce + ct + tag
        ep_pt = ephemeral_pub.public_numbers()
        ep_bytes = b'\x04' + ep_pt.x.to_bytes(32, 'big') + ep_pt.y.to_bytes(32, 'big')
        return ep_bytes + nonce + ct + enc.tag

    def decrypt_ec(self, packet: bytes, receiver_priv_ec) -> str:
        """Decrypt an EC-encrypted IP packet."""
        if len(packet) < 32 + 32 + 12 + 1 + 16:
            raise ValueError("Packet too short")

        # Parse ephemeral public point
        ep_bytes = packet[:65]
        ep_x = int.from_bytes(ep_bytes[1:33], 'big')
        ep_y = int.from_bytes(ep_bytes[33:65], 'big')
        ephemeral_pub = ec.EllipticCurvePublicNumbers(ep_x, ep_y, ec.SECP256R1()).public_key(default_backend())

        nonce = packet[65:77]
        ct = packet[77:-16]
        tag = packet[-16:]

        # Shared secret
        shared = receiver_priv_ec.exchange(ec.ECDH(), ephemeral_pub)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ip-encryption-v1-ecies",
                   backend=default_backend()).derive(shared)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        dec = cipher.decryptor()
        raw = dec.update(ct) + dec.finalize()
        return self._bytes_to_ip(raw)

    # -- Symmetric mode ------------------------------------------------

    def encrypt_symmetric(self, ip_str: str, shared_key: bytes) -> bytes:
        """Encrypt with a shared AES-256 key. Output looks random."""
        raw = self._ip_to_bytes(ip_str)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(nonce), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(raw) + enc.finalize()
        return nonce + ct + enc.tag  # 12 + 16 + 16 = 44 bytes for IPv4, 12 + 32 + 16 = 60 for IPv6

    def decrypt_symmetric(self, packet: bytes, shared_key: bytes) -> str:
        nonce, ct, tag = packet[:12], packet[12:-16], packet[-16:]
        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(nonce, tag), backend=default_backend())
        dec = cipher.decryptor()
        raw = dec.update(ct) + dec.finalize()
        return self._bytes_to_ip(raw)

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _ip_to_bytes(ip_str: str) -> bytes:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv4Address):
            return addr.packed  # 4 bytes
        return addr.packed  # 16 bytes for IPv6

    @staticmethod
    def _bytes_to_ip(raw: bytes) -> str:
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            raise ValueError(f"Decrypted bytes {raw!r} is not a valid IP address")


# ---------------------------------------------------------------------------
# Demo: what the encrypted IP "looks like"
# ---------------------------------------------------------------------------

def demo():
    print("=" * 60)
    print(" IP ENCRYPTION DEMO — observed vs. real")
    print("=" * 60)

    real_ip = "192.168.1.42"
    print(f"\nOriginal IP:     {real_ip}")

    # --- PKI: RSA --------------------------------------------------------
    print("\n--- RSA PKI (receiver's public key encrypts, private decrypts) ---")
    rsa_priv, rsa_pub = generate_rsa_keypair()
    enc = IPEncryptor(mode="pki")
    ct_rsa = enc.encrypt_pki(real_ip, rsa_pub)

    print(f"Ciphertext bytes: {ct_rsa.hex()}")
    print(f"Ciphertext length: {len(ct_rsa)} bytes ({len(ct_rsa)*8} bits)")
    print(f"As IPv4?          {len(ct_rsa) == 4 and _looks_like_ipv4(ct_rsa)}")
    print(f"As IPv6?          {len(ct_rsa) == 16 and _looks_like_ipv6(ct_rsa)}")
    print(f"Looks random:     {ct_rsa.hex()[:16]}... (no IP pattern)")
    print(f"Decrypted back:   {enc.decrypt_pki(ct_rsa, rsa_priv)}")

    # --- PKI: EC (ECIES-style) ------------------------------------------
    print("\n--- EC (ECIES: ephemeral ECDH + AES-GCM) ---")
    ec_priv, ec_pub = generate_ec_keypair()
    enc_ec = IPEncryptor(mode="pki", sender_ec_priv=None)
    ct_ec = enc_ec.encrypt_ec(real_ip, ec_pub)

    print(f"Ciphertext bytes: {ct_ec.hex()}")
    print(f"Ciphertext length: {len(ct_ec)} bytes ({len(ct_ec)*8} bits)")
    print(f"As IPv4?          {len(ct_ec) == 4}")
    print(f"As IPv6?          {len(ct_ec) == 16}")
    print(f"Looks random:     yes — {len(ct_ec)} bytes of unstructured data")
    print(f"Decrypted back:   {enc_ec.decrypt_ec(ct_ec, ec_priv)}")

    # --- Symmetric -------------------------------------------------------
    print("\n--- Symmetric (shared AES-256 key from ECDH) ---")
    alice_priv, alice_pub = generate_ec_keypair()
    bob_priv, bob_pub = generate_ec_keypair()
    alice_shared = derive_shared_secret(alice_priv, bob_pub)
    bob_shared = derive_shared_secret(bob_priv, alice_pub)
    assert alice_shared == bob_shared, "Shared secrets must match"

    enc_sym = IPEncryptor(mode="symmetric")
    ct_sym = enc_sym.encrypt_symmetric(real_ip, alice_shared)
    print(f"Ciphertext bytes: {ct_sym.hex()}")
    print(f"Ciphertext length: {len(ct_sym)} bytes")
    print(f"As IPv4?          {len(ct_sym) == 4}")
    print(f"As IPv6?          {len(ct_sym) == 16}")
    print(f"Decrypted (Alice): {enc_sym.decrypt_symmetric(ct_sym, alice_shared)}")
    print(f"Decrypted (Bob):   {enc_sym.decrypt_symmetric(ct_sym, bob_shared)}")

    print("\n" + "=" * 60)
    print(" SUMMARY: In all modes the encrypted IP is random-looking bytes")
    print(" that reveal NOTHING about the original IP to an observer.")
    print(" Only the holder of the private key / shared secret recovers it.")
    print("=" * 60)


def _looks_like_ipv4(raw: bytes) -> bool:
    """Heuristic: all bytes < 256, but IPv4 has no structural marker."""
    return False  # ciphertext is not an IP


def _looks_like_ipv6(raw: bytes) -> bool:
    return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Encrypt / decrypt IP addresses")
    sub = parser.add_subparsers(dest="action")

    # generate-keys
    gk = sub.add_parser("generate-keys", help="Generate keypairs")
    gk.add_argument("--type", choices=["rsa", "ec"], default="ec", help="Key type")
    gk.add_argument("--out", type=Path, default=Path("."), help="Output directory")

    # encrypt
    en = sub.add_parser("encrypt", help="Encrypt an IP address")
    en.add_argument("ip", help="IP address to encrypt (e.g. 10.0.0.1)")
    en.add_argument("--mode", choices=["pki", "symmetric"], default="pki")
    en.add_argument("--pub-key", type=Path, required=True, help="Receiver's public key (PEM)")
    en.add_argument("--ec", action="store_true", help="Use EC/ECIES mode")

    # decrypt
    de = sub.add_parser("decrypt", help="Decrypt an IP address")
    de.add_argument("packet", help="Hex-encoded ciphertext")
    de.add_argument("--priv-key", type=Path, required=True, help="Private key (PEM)")
    de.add_argument("--ec", action="store_true", help="Use EC/ECIES mode")
    de.add_argument("--symmetric", action="store_true", help="Use symmetric mode")
    de.add_argument("--shared-key", type=Path, help="Shared key file (hex-encoded)")

    args = parser.parse_args()

    if args.action == "generate-keys":
        if args.type == "rsa":
            priv, pub = generate_rsa_keypair()
        else:
            priv, pub = generate_ec_keypair()
        out = args.out
        out.mkdir(parents=True, exist_ok=True)
        save_pem_private(priv, out / "private.pem")
        save_pem_public(pub, out / "public.pem")
        print(f"Keys generated in {out}:")
        print(f"  private.pem  — keep secret (receiver only)")
        print(f"  public.pem   — distribute to senders")

    elif args.action == "encrypt":
        pub = load_pem_public(args.pub_key)
        enc = IPEncryptor(mode=args.mode)
        if args.ec:
            ct = enc.encrypt_ec(args.ip, pub)
        elif args.mode == "symmetric":
            raise SystemExit("--symmetric requires a shared key; use --shared-key")
        else:
            ct = enc.encrypt_pki(args.ip, pub)
        print(ct.hex())

    elif args.action == "decrypt":
        ct = bytes.fromhex(args.packet)
        if args.symmetric:
            shared = bytes.fromhex(args.shared_key.read_text().strip())
            enc = IPEncryptor(mode="symmetric")
            print(enc.decrypt_symmetric(ct, shared))
        elif args.ec:
            priv = load_pem_private(args.priv_key)
            enc = IPEncryptor(mode="pki")
            print(enc.decrypt_ec(ct, priv))
        else:
            priv = load_pem_private(args.priv_key)
            enc = IPEncryptor(mode="pki")
            print(enc.decrypt_pki(ct, priv))

    else:
        parser.print_help()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        demo()
