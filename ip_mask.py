#!/usr/bin/env python3
"""
Raw Packet IP Masking — decoy source IP in the header, encrypted real IP
in the payload.  Observers see only the decoy; the receiver decrypts the
payload to recover the real source IP.

Privileges: sending/capturing raw packets needs CAP_NET_RAW or root.
            Building/inspecting packets locally needs nothing.

Usage:
  # --- SENDER (encrypt + embed in raw packet) ---
  python3 ip_mask.py send \
      --dst 10.0.0.2 \
      --decoy 10.99.99.99 \
      --real-ip 192.168.1.42 \
      --pub-key ./keys/public.pem \
      [--iface eth0] [--ec]

  # --- BUILD ONLY (no send, print hex for inspection) ---
  python3 ip_mask.py build \
      --dst 10.0.0.2 \
      --decoy 10.99.99.99 \
      --real-ip 192.168.1.42 \
      --pub-key ./keys/public.pem \
      [--ec] [--pcap out.pcap]

  # --- SAVE TO PCAP (for later replay with tcpreplay / scapy) ---
  python3 ip_mask.py save \
      --dst 10.0.0.2 \
      --decoy 10.99.99.99 \
      --real-ip 192.168.1.42 \
      --pub-key ./keys/public.pem \
      --out packets.pcap \
      [--count 10] [--decoy-pool "10.99.99.99,10.98.98.98,172.16.0.1"] [--ec]

  # --- RECEIVER (capture + decrypt) ---
  sudo python3 ip_mask.py capture \
      --iface eth0 \
      --priv-key ./keys/private.pem \
      [--ec] [--host 10.0.0.2]

  # --- REPLAY a pcap file ---
  sudo tcpreplay -i eth0 packets.pcap

Protocol design (payload):
  Payload = [1 byte: version] [encrypted IP bytes]
  Version 1 = RSA-OAEP encrypted IP (256 bytes for 2048-bit RSA)
  Version 2 = ECIES encrypted IP (~97 bytes)
  Version 3 = Symmetric AES-GCM encrypted IP (32 bytes for IPv4)

  The receiver reads the version byte, then decrypts accordingly.
"""

import argparse
import ipaddress
import os
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ============================================================================
# Encryption  (same as ip_encrypt.py, re-exported here for standalone use)
# ============================================================================

def generate_ec_keypair():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return priv, priv.public_key()


def generate_rsa_keypair(key_size: int = 2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size,
                                     backend=default_backend())
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
    return serialization.load_pem_private_key(path.read_bytes(), password=None,
                                              backend=default_backend())


def load_pem_public(path: Path):
    return serialization.load_pem_public_key(path.read_bytes(), backend=default_backend())


def _ip_to_bytes(ip_str: str) -> bytes:
    addr = ipaddress.ip_address(ip_str)
    return addr.packed


def _bytes_to_ip(raw: bytes) -> str:
    return str(ipaddress.ip_address(raw))


# ---- RSA ----
def encrypt_rsa(ip_str: str, pub_key) -> bytes:
    raw = _ip_to_bytes(ip_str)
    return pub_key.encrypt(raw, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))


def decrypt_rsa(ct: bytes, priv_key) -> str:
    raw = priv_key.decrypt(ct, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    return _bytes_to_ip(raw)


# ---- ECIES (ephemeral ECDH + AES-GCM) ----
def encrypt_ecies(ip_str: str, receiver_pub_ec) -> bytes:
    raw = _ip_to_bytes(ip_str)
    ephemeral_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_pub = ephemeral_priv.public_key()
    shared = ephemeral_priv.exchange(ec.ECDH(), receiver_pub_ec)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"ip-mask-v1-ecies", backend=default_backend()).derive(shared)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(raw) + enc.finalize()
    ep_pt = ephemeral_pub.public_numbers()
    ep_bytes = (b'\x04'
                + ep_pt.x.to_bytes(32, 'big')
                + ep_pt.y.to_bytes(32, 'big'))
    return ep_bytes + nonce + ct + enc.tag  # 65 + 12 + 4or16 + 16


def decrypt_ecies(packet: bytes, receiver_priv_ec) -> str:
    ep_bytes = packet[:65]
    ep_x = int.from_bytes(ep_bytes[1:33], 'big')
    ep_y = int.from_bytes(ep_bytes[33:65], 'big')
    ephemeral_pub = ec.EllipticCurvePublicNumbers(ep_x, ep_y, ec.SECP256R1()
                                                   ).public_key(default_backend())
    nonce, ct, tag = packet[65:77], packet[77:-16], packet[-16:]
    shared = receiver_priv_ec.exchange(ec.ECDH(), ephemeral_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"ip-mask-v1-ecies", backend=default_backend()).derive(shared)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    dec = cipher.decryptor()
    raw = dec.update(ct) + dec.finalize()
    return _bytes_to_ip(raw)


# ---- Symmetric ----
def encrypt_symmetric(ip_str: str, shared_key: bytes) -> bytes:
    raw = _ip_to_bytes(ip_str)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(shared_key), modes.GCM(nonce), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(raw) + enc.finalize()
    return nonce + ct + enc.tag


def decrypt_symmetric(packet: bytes, shared_key: bytes) -> str:
    nonce, ct, tag = packet[:12], packet[12:-16], packet[-16:]
    cipher = Cipher(algorithms.AES(shared_key), modes.GCM(nonce, tag), backend=default_backend())
    dec = cipher.decryptor()
    raw = dec.update(ct) + dec.finalize()
    return _bytes_to_ip(raw)


# ============================================================================
# Packet construction
# ============================================================================

IP_VERSION = 4
IP_IHL = 5  # 20 bytes, no options
IP_DSCP_ECN = 0
IP_FLAGS_DF = 0x4000  # Don't fragment
IP_TTL = 64
IP_PROTOCOL_CUSTOM = 253  # Experimental/unknown — looks like garbage to scanners

# PCAP constants
PCAP_MAGIC = 0xa1b2c3d4       # Standard pcap magic (microsecond timestamps)
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAplen = 65535
PCAP_LINKTYPE_RAW = 101        # Raw IP packets (no Ethernet header)


class RawPacket:
    """Builds a raw IPv4 packet with a decoy source IP and encrypted payload."""

    def __init__(self, dst_ip: str, decoy_ip: str, payload: bytes,
                 protocol: int = IP_PROTOCOL_CUSTOM):
        self.dst = dst_ip
        self.decoy = decoy_ip
        self.payload = payload
        self.protocol = protocol

    def build(self) -> bytes:
        """Return the complete IP packet as bytes."""
        hdr_len = IP_IHL * 4
        total_len = hdr_len + len(self.payload)

        # -- IP header fields --
        version_ihl = (IP_VERSION << 4) | IP_IHL
        dscp_ecn = IP_DSCP_ECN
        total_length = total_len
        identification = os.urandom(2)  # random
        flags_frag = IP_FLAGS_DF
        ttl = IP_TTL
        proto = self.protocol
        header_checksum = 0  # compute below
        src = ipaddress.ip_address(self.decoy).packed
        dst = ipaddress.ip_address(self.dst).packed

        hdr = struct.pack('!BBHHHBBH4s4s',
                          version_ihl, dscp_ecn, total_length,
                          struct.unpack('!H', identification)[0],
                          flags_frag, ttl, proto, header_checksum,
                          src, dst)

        # -- checksum --
        checksum = _ip_checksum(hdr)
        hdr = struct.pack('!BBHHHBBH4s4s',
                          version_ihl, dscp_ecn, total_length,
                          struct.unpack('!H', identification)[0],
                          flags_frag, ttl, proto, checksum,
                          src, dst)

        return hdr + self.payload

    def inspect(self) -> dict:
        """Return human-readable packet details."""
        pkt = self.build()
        hdr = pkt[:20]
        fields = struct.unpack('!BBHHHBBH4s4s', hdr)
        return {
            'total_length': fields[2],
            'identification': hex(fields[3]),
            'flags_fragment': hex(fields[4]),
            'ttl': fields[5],
            'protocol': fields[6],
            'src_ip': ipaddress.ip_address(fields[8]).exploded,
            'dst_ip': ipaddress.ip_address(fields[9]).exploded,
            'payload_len': len(pkt) - 20,
            'payload_hex': pkt[20:].hex(),
            'raw_hex': pkt.hex(),
        }


def _ip_checksum(header: bytes) -> int:
    """RFC 1071 IP header checksum."""
    if len(header) % 2:
        header += b'\x00'
    s = 0
    for i in range(0, len(header), 2):
        w = (header[i] << 8) + header[i + 1]
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ============================================================================
# Sending / Capturing
# ============================================================================

def send_raw_packet(packet_bytes: bytes, dst_ip: str, iface: str = None,
                    protocol: int = IP_PROTOCOL_CUSTOM):
    """
    Send a raw IP packet. Requires CAP_NET_RAW or root.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
    except PermissionError:
        raise PermissionError(
            "Raw sockets require CAP_NET_RAW or root. "
            "Run with: sudo python3 ip_mask.py ..."
        )
    # IP_HDRINCL tells the kernel we supply the full IP header (including src)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    if iface:
        # Bind to specific interface (Linux-specific)
        try:
            s.bind((iface, 0))
        except Exception:
            pass  # non-Linux or interface name mismatch — ignore
    s.sendto(packet_bytes, (dst_ip, 0))
    s.close()


def _capture_raw_socket(iface: str = None, host_ip: str = None,
                       protocol: int = IP_PROTOCOL_CUSTOM):
    """
    Create a raw socket for capturing. Requires CAP_NET_RAW or root.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
    except PermissionError:
        raise PermissionError(
            "Packet capture requires CAP_NET_RAW or root. "
            "Run with: sudo python3 ip_mask.py capture ..."
        )
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    if host_ip:
        s.bind((host_ip, 0))
    if iface:
        try:
            s.bind((iface, 0))
        except Exception:
            pass
    # Include IP headers in received data
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s


# ============================================================================
# PCAP export
# ============================================================================

def write_pcap(path: Path, packets: list[tuple[bytes, float | None]],
               linktype: int = PCAP_LINKTYPE_RAW):
    """
    Write packets to a pcap file.

    packets: list of (raw_packet_bytes, timestamp_or_none)
             timestamp is seconds since epoch (float) or None for current time.
    linktype: pcap link-layer type. PCAP_LINKTYPE_RAW (101) = raw IP, no Ethernet.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open('wb') as f:
        # --- Global header (24 bytes) ---
        f.write(struct.pack('<IHHiIII',
                             PCAP_MAGIC,
                             PCAP_VERSION_MAJOR,
                             PCAP_VERSION_MINOR,
                             0,              # thiszone (GMT)
                             0,              # sigfigs
                             PCAP_SNAplen,
                             linktype))

        # --- Packet records ---
        for pkt_bytes, ts in packets:
            if ts is None:
                ts = time.time()
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            caught_len = len(pkt_bytes)
            orig_len = len(pkt_bytes)
            f.write(struct.pack('<IIII', sec, usec, caught_len, orig_len))
            f.write(pkt_bytes)

    pcap_size = path.stat().st_size
    print(f"PCAP saved: {path} ({len(packets)} packet(s), {pcap_size} bytes, linktype={linktype})")


# ============================================================================
# CLI
# ============================================================================

def cmd_generate_keys(args):
    if args.type == "rsa":
        priv, pub = generate_rsa_keypair()
    else:
        priv, pub = generate_ec_keypair()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    save_pem_private(priv, out / "private.pem")
    save_pem_public(pub, out / "public.pem")
    print(f"Keys in {out}/")
    print(f"  private.pem  (receiver only)")
    print(f"  public.pem   (distribute to senders)")


def cmd_build(args):
    pub = load_pem_public(args.pub_key)
    real_ip = args.real_ip
    decoy_ip = args.decoy

    # Encrypt
    if args.ec:
        payload = encrypt_ecies(real_ip, pub)
        version = 2
    else:
        payload = encrypt_rsa(real_ip, pub)
        version = 1

    # Prepend version byte
    full_payload = bytes([version]) + payload

    # Build packet
    pkt = RawPacket(dst_ip=args.dst, decoy_ip=decoy_ip, payload=full_payload,
                    protocol=IP_PROTOCOL_CUSTOM)
    info = pkt.inspect()

    # Optionally also save to pcap
    if args.pcap:
        write_pcap(args.pcap, [(pkt.build(), None)])
        print(f"[PCAP saved to {args.pcap}]")

    print("=== Built Packet (not sent) ===")
    print(f"  Source IP (decoy):  {info['src_ip']}")
    print(f"  Dest IP:             {info['dst_ip']}")
    print(f"  Protocol:            {info['protocol']} (experimental)")
    print(f"  TTL:                 {info['ttl']}")
    print(f"  Total length:        {info['total_length']} bytes")
    print(f"  Payload length:      {info['payload_len']} bytes")
    print(f"  Payload hex:         {info['payload_hex']}")
    print(f"  Full packet hex:     {info['raw_hex']}")
    print()
    print("To an observer this looks like:")
    print(f"  IP packet from {info['src_ip']} → {info['dst_ip']}")
    print(f"  Protocol {info['protocol']} (unknown/experimental)")
    print(f"  {info['payload_len']} bytes of payload with no visible IP pattern")
    print()
    print("Only the receiver with the matching private key can extract")
    print(f"the real IP ({real_ip}) from the payload.")


def cmd_send(args):
    pub = load_pem_public(args.pub_key)
    real_ip = args.real_ip
    decoy_ip = args.decoy
    dst_ip = args.dst

    if args.ec:
        payload = encrypt_ecies(real_ip, pub)
        version = 2
    else:
        payload = encrypt_rsa(real_ip, pub)
        version = 1

    full_payload = bytes([version]) + payload
    pkt = RawPacket(dst_ip=dst_ip, decoy_ip=decoy_ip, payload=full_payload,
                    protocol=IP_PROTOCOL_CUSTOM)
    packet_bytes = pkt.build()

    print(f"Sending {len(packet_bytes)} bytes:")
    print(f"  Decoy src: {decoy_ip} → Dst: {dst_ip}")
    print(f"  Embedded real IP ({real_ip}) encrypted in payload")

    # Optionally save a copy to pcap as well
    if args.pcap:
        write_pcap(args.pcap, [(packet_bytes, None)])

    try:
        send_raw_packet(packet_bytes, dst_ip, args.iface, IP_PROTOCOL_CUSTOM)
        print("Packet sent.")
    except PermissionError as e:
        print(f"ERROR: {e}")
        print("Build the packet with 'build' subcommand to see the hex,")
        print("then send it from a machine with CAP_NET_RAW/root.")
        sys.exit(1)


def cmd_save(args):
    """Build packet(s) and save to a pcap file for later replay."""
    pub = load_pem_public(args.pub_key)
    real_ip = args.real_ip
    decoy_ip = args.decoy
    dst_ip = args.dst
    out_path = args.out

    if args.ec:
        payload = encrypt_ecies(real_ip, pub)
        version = 2
        method = "ECIES"
    else:
        payload = encrypt_rsa(real_ip, pub)
        version = 1
        method = "RSA-OAEP"

    full_payload = bytes([version]) + payload

    # Single packet or multiple (with random decoys)
    if args.count and args.count > 1:
        import random as _rnd
        packets = []
        pool = [ip.strip() for ip in args.decoy_pool.split(',')]\
               if args.decoy_pool else [decoy_ip]
        for _ in range(args.count):
            d = _rnd.choice(pool)
            p = RawPacket(dst_ip=dst_ip, decoy_ip=d, payload=full_payload,
                          protocol=IP_PROTOCOL_CUSTOM)
            packets.append((p.build(), None))
        decoy_desc = f"pool of {len(pool)}: {', '.join(pool)}"
    else:
        packets = [(RawPacket(dst_ip=dst_ip, decoy_ip=decoy_ip,
                               payload=full_payload,
                               protocol=IP_PROTOCOL_CUSTOM).build(), None)]
        decoy_desc = decoy_ip

    write_pcap(out_path, packets)

    print(f"\nReal IP ({real_ip}) encrypted via {method} in {len(packets)} packet(s).")
    print(f"Decoy IP(s): {decoy_desc}")
    print(f"\nTo replay later:")
    print(f"  sudo tcpreplay -i <iface> {out_path}")
    print(f"  # or with scapy:")
    print(f"  #   from scapy.all import *")
    print(f"  #   packets = rdpcap('{out_path}')")
    print(f"  #   sendp(packets, iface='<iface>')")


def cmd_capture(args):
    priv = load_pem_private(args.priv_key)
    host_ip = args.host
    iface = args.iface
    protocol = IP_PROTOCOL_CUSTOM

    print(f"Listening for protocol-{protocol} packets (Ctrl-C to stop)...")
    print(f"  iface={iface or 'any'}, host={host_ip or '0.0.0.0'}")
    print()

    try:
        sock = _capture_raw_socket(iface, host_ip, protocol)
    except PermissionError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    try:
        while True:
            # recvfrom on raw socket gives (packet_data, (src, port, info))
            data, addr = sock.recvfrom(65535)
            # Strip IP header (20 bytes) to get payload
            if len(data) < 21:
                continue
            ip_hdr = data[:20]
            payload = data[20:]

            # Parse IP header to show decoy
            hdr_fields = struct.unpack('!BBHHHBBH4s4s', ip_hdr)
            decoy_src = ipaddress.ip_address(hdr_fields[8]).exploded
            pkt_dst = ipaddress.ip_address(hdr_fields[9]).exploded

            if len(payload) < 2:
                continue

            version = payload[0]
            ct = payload[1:]

            try:
                if version == 1:
                    real_ip = decrypt_rsa(ct, priv)
                    method = "RSA-OAEP"
                elif version == 2:
                    real_ip = decrypt_ecies(ct, priv)
                    method = "ECIES"
                elif version == 3:
                    # Symmetric — needs shared key, not private key
                    print(f"  [version 3 = symmetric, need shared key]")
                    continue
                else:
                    print(f"  Unknown version {version}")
                    continue

                print(f"[DECRYPTED] {time.strftime('%H:%M:%S')}")
                print(f"  Decoy src: {decoy_src} → Dst: {pkt_dst}")
                print(f"  Real IP:   {real_ip}  (via {method})")
                print(f"  Payload:   {ct.hex()}")
                print()

            except Exception as e:
                print(f"[FAILED]  {decoy_src} → {pkt_dst}: {e}")

    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="Raw packet IP masking: decoy IP in header, encrypted real IP in payload")
    sub = parser.add_subparsers(dest="action")

    # generate-keys
    gk = sub.add_parser("generate-keys", help="Generate keypairs")
    gk.add_argument("--type", choices=["rsa", "ec"], default="ec", help="Key type")
    gk.add_argument("--out", type=Path, default=Path("./keys"), help="Output directory")

    # build
    bd = sub.add_parser("build", help="Build packet (don't send, show hex)")
    bd.add_argument("--dst", required=True, help="Destination IP")
    bd.add_argument("--decoy", required=True, help="Decoy source IP (what observers see)")
    bd.add_argument("--real-ip", required=True, help="Real IP to hide")
    bd.add_argument("--pub-key", type=Path, required=True, help="Receiver's public key (PEM)")
    bd.add_argument("--ec", action="store_true", help="Use ECIES (EC) mode")
    bd.add_argument("--pcap", type=Path, help="Also save to pcap file")

    # send
    sd = sub.add_parser("send", help="Build and send raw packet")
    sd.add_argument("--dst", required=True, help="Destination IP")
    sd.add_argument("--decoy", required=True, help="Decoy source IP")
    sd.add_argument("--real-ip", required=True, help="Real IP to hide")
    sd.add_argument("--pub-key", type=Path, required=True, help="Receiver's public key (PEM)")
    sd.add_argument("--iface", help="Network interface (e.g. eth0)")
    sd.add_argument("--ec", action="store_true", help="Use ECIES (EC) mode")
    sd.add_argument("--pcap", type=Path, help="Also save a copy to pcap file")

    # save (pcap-only, no send)
    sv = sub.add_parser("save", help="Build packet(s) and save to pcap for later replay")
    sv.add_argument("--dst", required=True, help="Destination IP")
    sv.add_argument("--decoy", required=True, help="Decoy source IP (single packet mode)")
    sv.add_argument("--real-ip", required=True, help="Real IP to hide")
    sv.add_argument("--pub-key", type=Path, required=True, help="Receiver's public key (PEM)")
    sv.add_argument("--out", type=Path, required=True, help="Output pcap file path")
    sv.add_argument("--count", type=int, default=1, help="Number of packets to generate")
    sv.add_argument("--decoy-pool", help="Comma-separated decoy IPs for multi-packet mode")
    sv.add_argument("--ec", action="store_true", help="Use ECIES (EC) mode")

    # capture
    cp = sub.add_parser("capture", help="Listen and decrypt incoming packets")
    cp.add_argument("--priv-key", type=Path, required=True, help="Receiver's private key (PEM)")
    cp.add_argument("--iface", help="Interface to listen on")
    cp.add_argument("--host", help="Host IP to bind to")
    cp.add_argument("--ec", action="store_true", help="Use ECIES mode")

    args = parser.parse_args()

    if not args.action:
        parser.print_help()
        sys.exit(1)

    {
        "generate-keys": cmd_generate_keys,
        "build": cmd_build,
        "send": cmd_send,
        "save": cmd_save,
        "capture": cmd_capture,
    }[args.action](args)


if __name__ == "__main__":
    main()
