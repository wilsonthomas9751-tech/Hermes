#!/usr/bin/env python3
"""
IP Masking Tool — Windows Edition
==================================
Uses scapy + Npcap for raw packet send/capture on Windows.
Also works on Linux (falls back to raw sockets).

Requires:
  - Python 3.7+
  - cryptography library
  - scapy + Npcap (Windows send/capture only)

Usage:
  # Key generation (cross-platform)
  python ip_mask_windows.py generate-keys --type ec --out .\\keys

  # Build packet (cross-platform, no special deps)
  python ip_mask_windows.py build --dst 10.0.0.2 --decoy 10.99.99.99 ...

  # Save to pcap (cross-platform)
  python ip_mask_windows.py save --dst 10.0.0.2 --decoy 10.99.99.99 ... --out packets.pcap

  # Send via Npcap (Windows, requires admin + Npcap)
  python ip_mask_windows.py send --dst 10.0.0.2 --decoy 10.99.99.99 ... --iface Ethernet

  # Capture + decrypt via Npcap (Windows, requires admin + Npcap)
  python ip_mask_windows.py capture --priv-key .\\keys\\private.pem --iface Ethernet

  # Run as Windows Service (see install-service.bat)
"""

import argparse
import ipaddress
import os
import struct
import sys
import time
from pathlib import Path

# ============================================================================
# Try importing scapy (Windows send/capture)
# ============================================================================
try:
    from scapy.all import IP, Raw, sniff, send, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================================================================
# Encryption — same as Linux version, cross-platform
# ============================================================================

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


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
    return ep_bytes + nonce + ct + enc.tag


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


# ============================================================================
# Packet construction
# ============================================================================

IP_VERSION = 4
IP_IHL = 5
IP_DSCP_ECN = 0
IP_FLAGS_DF = 0x4000
IP_TTL = 64
IP_PROTOCOL_CUSTOM = 253


class RawPacket:
    """Builds a raw IPv4 packet with a decoy source IP and encrypted payload."""

    def __init__(self, dst_ip: str, decoy_ip: str, payload: bytes,
                 protocol: int = IP_PROTOCOL_CUSTOM):
        self.dst = dst_ip
        self.decoy = decoy_ip
        self.payload = payload
        self.protocol = protocol

    def build(self) -> bytes:
        hdr_len = IP_IHL * 4
        total_len = hdr_len + len(self.payload)

        version_ihl = (IP_VERSION << 4) | IP_IHL
        identification = os.urandom(2)
        src = ipaddress.ip_address(self.decoy).packed
        dst = ipaddress.ip_address(self.dst).packed

        hdr = struct.pack('!BBHHHBBH4s4s',
                          version_ihl, IP_DSCP_ECN, total_len,
                          struct.unpack('!H', identification)[0],
                          IP_FLAGS_DF, IP_TTL, self.protocol, 0,
                          src, dst)
        checksum = _ip_checksum(hdr)
        hdr = struct.pack('!BBHHHBBH4s4s',
                          version_ihl, IP_DSCP_ECN, total_len,
                          struct.unpack('!H', identification)[0],
                          IP_FLAGS_DF, IP_TTL, self.protocol, checksum,
                          src, dst)
        return hdr + self.payload

    def inspect(self) -> dict:
        pkt = self.build()
        hdr = pkt[:20]
        fields = struct.unpack('!BBHHHBBH4s4s', hdr)
        return {
            'total_length': fields[2],
            'src_ip': ipaddress.ip_address(fields[8]).exploded,
            'dst_ip': ipaddress.ip_address(fields[9]).exploded,
            'protocol': fields[6],
            'ttl': fields[5],
            'payload_len': len(pkt) - 20,
            'payload_hex': pkt[20:].hex(),
            'raw_hex': pkt.hex(),
        }


def _ip_checksum(header: bytes) -> int:
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
# PCAP export (cross-platform)
# ============================================================================

PCAP_MAGIC = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAplen = 65535
PCAP_LINKTYPE_RAW = 101


def write_pcap(path: Path, packets: list[tuple[bytes, float | None]],
               linktype: int = PCAP_LINKTYPE_RAW):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('wb') as f:
        f.write(struct.pack('<IHHiIII',
                             PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
                             0, 0, PCAP_SNAplen, linktype))
        for pkt_bytes, ts in packets:
            if ts is None:
                ts = time.time()
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack('<IIII', sec, usec, len(pkt_bytes), len(pkt_bytes)))
            f.write(pkt_bytes)
    print(f"PCAP saved: {path} ({len(packets)} packet(s), {path.stat().st_size} bytes)")


# ============================================================================
# Windows: Scapy-based send / capture
# ============================================================================

def send_scapy(packet_bytes: bytes, dst_ip: str, iface: str = None):
    """Send a raw IP packet using scapy + Npcap. Requires admin + Npcap."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "scapy not available. Install: pip install scapy\n"
            "Then install Npcap: https://npcap.com/#install\n"
            "Run as Administrator."
        )
    # Scapy wants an IP layer + Raw payload
    pkt = IP(src=_get_decoy_from_packet(packet_bytes), dst=dst_ip,
             proto=IP_PROTOCOL_CUSTOM) / Raw(load=_get_payload_from_packet(packet_bytes))
    if iface:
        send(pkt, iface=iface, verbose=False)
    else:
        send(pkt, verbose=False)
    print("Packet sent via Npcap.")


def _get_decoy_from_packet(packet_bytes: bytes) -> str:
    """Extract decoy source IP from built packet bytes."""
    src_bytes = packet_bytes[12:16]
    return ipaddress.ip_address(src_bytes).exploded


def _get_payload_from_packet(packet_bytes: bytes) -> bytes:
    """Extract payload from built packet bytes."""
    return packet_bytes[20:]


def capture_scapy(priv_key, iface: str = None, host_ip: str = None,
                  ec_mode: bool = False, log_file: str = None):
    """Capture and decrypt packets using scapy + Npcap. Requires admin + Npcap."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy not available. See install instructions.")

    priv = priv_key
    log_fh = None
    if log_file:
        log_fh = open(log_file, 'a')

    def handle_packet(pkt):
        try:
            if not pkt.haslayer(IP):
                return
            if pkt[IP].proto != IP_PROTOCOL_CUSTOM:
                return
            if not pkt.haslayer(Raw):
                return

            ip_hdr = bytes(pkt[IP].src).encode() if isinstance(pkt[IP].src, str) \
                      else pkt[IP].src
            # Scapy stores IP src as string
            decoy_src = pkt[IP].src
            pkt_dst = pkt[IP].dst

            raw_payload = bytes(pkt[Raw].load)
            if len(raw_payload) < 2:
                return

            version = raw_payload[0]
            ct = raw_payload[1:]

            try:
                if version == 1:
                    real_ip = decrypt_rsa(ct, priv)
                    method = "RSA-OAEP"
                elif version == 2:
                    real_ip = decrypt_ecies(ct, priv)
                    method = "ECIES"
                else:
                    return

                timestamp = time.strftime('%H:%M:%S')
                line = f"[{timestamp}] Decoy: {decoy_src} → {pkt_dst} | Real: {real_ip} ({method})\n"
                print(line, end='')
                if log_fh:
                    log_fh.write(line)
                    log_fh.flush()

            except Exception as e:
                print(f"[FAILED] {decoy_src} → {pkt_dst}: {e}\n")

        except Exception:
            pass  # skip malformed packets silently

    print(f"Listening for protocol-{IP_PROTOCOL_CUSTOM} packets (Ctrl-C to stop)...")
    if iface:
        print(f"  Interface: {iface}")
    filter_str = f"proto {IP_PROTOCOL_CUSTOM}"
    try:
        sniff(filter=filter_str, prn=handle_packet, iface=iface,
              store=False, promisc=True)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if log_fh:
            log_fh.close()


# ============================================================================
# Linux: raw socket send / capture (fallback)
# ============================================================================

def send_raw_packet(packet_bytes: bytes, dst_ip: str, iface: str = None):
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, IP_PROTOCOL_CUSTOM)
    except PermissionError:
        raise PermissionError("Root/CAP_NET_RAW required for raw sockets.")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    if iface:
        try:
            s.bind((iface, 0))
        except Exception:
            pass
    s.sendto(packet_bytes, (dst_ip, 0))
    s.close()


def _capture_raw_socket(iface: str = None, host_ip: str = None):
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, IP_PROTOCOL_CUSTOM)
    except PermissionError:
        raise PermissionError("Root/CAP_NET_RAW required for raw sockets.")
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    if host_ip:
        s.bind((host_ip, 0))
    if iface:
        try:
            s.bind((iface, 0))
        except Exception:
            pass
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s


def capture_raw(priv_key, iface: str = None, host_ip: str = None, ec_mode: bool = False):
    import socket
    sock = _capture_raw_socket(iface, host_ip)
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            if len(data) < 21:
                continue
            ip_hdr = data[:20]
            payload = data[20:]
            hdr_fields = struct.unpack('!BBHHHBBH4s4s', ip_hdr)
            decoy_src = ipaddress.ip_address(hdr_fields[8]).exploded
            pkt_dst = ipaddress.ip_address(hdr_fields[9]).exploded
            if len(payload) < 2:
                continue
            version = payload[0]
            ct = payload[1:]
            try:
                if version == 1:
                    real_ip = decrypt_rsa(ct, priv_key)
                    method = "RSA-OAEP"
                elif version == 2:
                    real_ip = decrypt_ecies(ct, priv_key)
                    method = "ECIES"
                else:
                    continue
                print(f"[{time.strftime('%H:%M:%S')}] {decoy_src} → {pkt_dst} | {real_ip} ({method})")
            except Exception as e:
                print(f"[FAILED] {decoy_src} → {pkt_dst}: {e}")
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()


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
    payload = encrypt_ecies(args.real_ip, pub) if args.ec else encrypt_rsa(args.real_ip, pub)
    version = 2 if args.ec else 1
    full_payload = bytes([version]) + payload
    pkt = RawPacket(dst_ip=args.dst, decoy_ip=args.decoy, payload=full_payload)
    info = pkt.inspect()

    if args.pcap:
        write_pcap(args.pcap, [(pkt.build(), None)])
        print(f"[PCAP saved to {args.pcap}]")

    print("=== Built Packet ===")
    print(f"  Source (decoy): {info['src_ip']}")
    print(f"  Dest:           {info['dst_ip']}")
    print(f"  Protocol:       {info['protocol']} (experimental)")
    print(f"  Total length:   {info['total_length']} bytes")
    print(f"  Payload hex:    {info['payload_hex']}")
    print(f"  Full hex:       {info['raw_hex']}")


def cmd_send(args):
    pub = load_pem_public(args.pub_key)
    payload = encrypt_ecies(args.real_ip, pub) if args.ec else encrypt_rsa(args.real_ip, pub)
    version = 2 if args.ec else 1
    full_payload = bytes([version]) + payload
    pkt = RawPacket(dst_ip=args.dst, decoy_ip=args.decoy, payload=full_payload)
    packet_bytes = pkt.build()

    print(f"Sending {len(packet_bytes)} bytes: {args.decoy} → {args.dst}")

    if args.pcap:
        write_pcap(args.pcap, [(packet_bytes, None)])

    # Try scapy first (Windows), fall back to raw sockets (Linux)
    if SCAPY_AVAILABLE and os.name == 'nt':
        try:
            send_scapy(packet_bytes, args.dst, args.iface)
            return
        except Exception as e:
            print(f"Scapy send failed: {e}")
            print("Falling back to raw socket...")
    # Linux raw socket
    try:
        send_raw_packet(packet_bytes, args.dst, args.iface)
        print("Packet sent.")
    except PermissionError as e:
        print(f"ERROR: {e}")
        print("Use 'build' or 'save' to create a pcap, then replay on a machine with raw socket access.")
        sys.exit(1)


def cmd_save(args):
    pub = load_pem_public(args.pub_key)
    payload = encrypt_ecies(args.real_ip, pub) if args.ec else encrypt_rsa(args.real_ip, pub)
    version = 2 if args.ec else 1
    full_payload = bytes([version]) + payload

    if args.count and args.count > 1:
        import random as _rnd
        pool = [ip.strip() for ip in args.decoy_pool.split(',')] if args.decoy_pool else [args.decoy]
        packets = []
        for _ in range(args.count):
            d = _rnd.choice(pool)
            p = RawPacket(dst_ip=args.dst, decoy_ip=d, payload=full_payload)
            packets.append((p.build(), None))
        decoy_desc = f"pool of {len(pool)}: {', '.join(pool)}"
    else:
        packets = [(RawPacket(dst_ip=args.dst, decoy_ip=args.decoy, payload=full_payload).build(), None)]
        decoy_desc = args.decoy

    write_pcap(args.out, packets)
    print(f"\nReal IP ({args.real_ip}) encrypted in {len(packets)} packet(s).")
    print(f"Decoy: {decoy_desc}")
    print(f"\nTo replay:")
    print(f"  Linux:   sudo tcpreplay -i <iface> {args.out}")
    print(f"  Windows: use Npcap + scapy or tcpreplay-win")


def cmd_capture(args):
    priv = load_pem_private(args.priv_key)

    # Scapy on Windows, raw sockets on Linux
    if SCAPY_AVAILABLE and os.name == 'nt':
        capture_scapy(priv, args.iface, args.host, args.ec, args.log_file)
    else:
        capture_raw(priv, args.iface, args.host, args.ec)


def main():
    parser = argparse.ArgumentParser(
        description="IP Masking — cross-platform (Windows: scapy+Npcap, Linux: raw sockets)")
    sub = parser.add_subparsers(dest="action")

    gk = sub.add_parser("generate-keys")
    gk.add_argument("--type", choices=["rsa", "ec"], default="ec")
    gk.add_argument("--out", type=Path, default=Path("./keys"))

    bd = sub.add_parser("build")
    bd.add_argument("--dst", required=True)
    bd.add_argument("--decoy", required=True)
    bd.add_argument("--real-ip", required=True)
    bd.add_argument("--pub-key", type=Path, required=True)
    bd.add_argument("--ec", action="store_true")
    bd.add_argument("--pcap", type=Path, help="Also save to pcap")

    sd = sub.add_parser("send")
    sd.add_argument("--dst", required=True)
    sd.add_argument("--decoy", required=True)
    sd.add_argument("--real-ip", required=True)
    sd.add_argument("--pub-key", type=Path, required=True)
    sd.add_argument("--iface", help="Network interface (e.g. Ethernet)")
    sd.add_argument("--ec", action="store_true")
    sd.add_argument("--pcap", type=Path, help="Also save to pcap")

    sv = sub.add_parser("save")
    sv.add_argument("--dst", required=True)
    sv.add_argument("--decoy", required=True)
    sv.add_argument("--real-ip", required=True)
    sv.add_argument("--pub-key", type=Path, required=True)
    sv.add_argument("--out", type=Path, required=True)
    sv.add_argument("--count", type=int, default=1)
    sv.add_argument("--decoy-pool", help="Comma-separated decoy IPs")
    sv.add_argument("--ec", action="store_true")

    cp = sub.add_parser("capture")
    cp.add_argument("--priv-key", type=Path, required=True)
    cp.add_argument("--iface", help="Interface (e.g. Ethernet)")
    cp.add_argument("--host", help="Host IP to bind")
    cp.add_argument("--ec", action="store_true")
    cp.add_argument("--log-file", help="Also log decrypted IPs to file")

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
    # Windows: warn if scapy missing for send/capture
    if os.name == 'nt' and not SCAPY_AVAILABLE:
        print("WARNING: scapy not installed. Send/capture won't work on Windows.")
        print("  Install: pip install scapy")
        print("  Download Npcap: https://npcap.com/#install (admin required)")
        print("  Build/save/pcap features still work without scapy.")
    main()
