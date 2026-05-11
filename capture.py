"""
capture.py — Network Packet Capture Module
==========================================
Handles live packet sniffing and loading saved .pcap files.
Requires: scapy, Npcap (Windows) or libpcap (Linux/Mac)
Run with administrator / sudo privileges for live capture.
"""

from scapy.all import (
    get_if_list, get_if_addr, sniff,
    wrpcap, rdpcap,
    IP, TCP, UDP, ICMP, ARP, DNS, Raw
)
from colorama import Fore, Style, init
import datetime
import os

init(autoreset=True)

# ─── Captured packet storage ───────────────────────────────────────────────
captured_packets = []


def list_interfaces():
    """Print all available network interfaces with their IP addresses."""
    print(f"\n{Fore.CYAN}[*] Available Network Interfaces:{Style.RESET_ALL}")
    print(f"{'─'*55}")
    ifaces = get_if_list()
    for idx, iface in enumerate(ifaces):
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "N/A"
        print(f"  {Fore.YELLOW}[{idx}]{Style.RESET_ALL} {iface:<35} {Fore.GREEN}{ip}{Style.RESET_ALL}")
    print(f"{'─'*55}\n")
    return ifaces


def packet_callback(pkt):
    """Callback fired for every captured packet — parses and prints a one-liner."""
    captured_packets.append(pkt)

    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    size = len(pkt)
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    if TCP in pkt:
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = str(pkt[TCP].flags)
        color = Fore.BLUE
        extra = f"port {sport} → {dport}  flags=[{flags}]"
    elif UDP in pkt:
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        color = Fore.CYAN
        extra = f"port {sport} → {dport}"
    elif ICMP in pkt:
        proto = "ICMP"
        color = Fore.MAGENTA
        extra = f"type={pkt[ICMP].type}"
    else:
        proto = "OTHER"
        color = Fore.WHITE
        extra = ""

    print(
        f"  {Fore.WHITE}{ts}{Style.RESET_ALL}  "
        f"{color}[{proto:5s}]{Style.RESET_ALL}  "
        f"{Fore.YELLOW}{src:<16}{Style.RESET_ALL} → "
        f"{Fore.GREEN}{dst:<16}{Style.RESET_ALL}  "
        f"{size:>5} B  {Fore.WHITE}{extra}{Style.RESET_ALL}"
    )


def start_capture(interface: str = "eth0", count: int = 200, save: bool = True) -> list:
    """
    Capture packets live from a network interface.

    Args:
        interface: Network interface name (e.g. 'eth0', 'Wi-Fi')
        count    : Number of packets to capture (0 = unlimited, Ctrl+C to stop)
        save     : Whether to save the capture to a .pcap file

    Returns:
        List of captured Scapy packet objects
    """
    global captured_packets
    captured_packets = []

    print(f"\n{Fore.GREEN}[+] Starting capture on interface: {Fore.YELLOW}{interface}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Capturing {count if count else 'unlimited'} packets "
          f"{'(Ctrl+C to stop)' if not count else ''}...{Style.RESET_ALL}\n")
    print(f"  {'Time':<10}  {'Proto':<7}  {'Source':<18} {'Dest':<18} {'Size':>6}  {'Detail'}")
    print(f"  {'─'*80}")

    try:
        sniff(iface=interface, prn=packet_callback, count=count, store=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Capture stopped by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Capture error: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Make sure you're running as administrator/sudo "
              f"and Npcap/libpcap is installed.{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}[+] Captured {len(captured_packets)} packets.{Style.RESET_ALL}")

    if save and captured_packets:
        os.makedirs("captures", exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"captures/capture_{ts}.pcap"
        wrpcap(fname, captured_packets)
        print(f"{Fore.GREEN}[+] Saved to: {Fore.CYAN}{fname}{Style.RESET_ALL}")

    return captured_packets


def load_capture(filepath: str) -> list:
    """
    Load packets from an existing .pcap file for offline analysis.

    Args:
        filepath: Path to the .pcap file

    Returns:
        List of Scapy packet objects
    """
    if not os.path.exists(filepath):
        print(f"{Fore.RED}[!] File not found: {filepath}{Style.RESET_ALL}")
        return []

    packets = rdpcap(filepath)
    print(f"{Fore.GREEN}[+] Loaded {len(packets)} packets from: {Fore.CYAN}{filepath}{Style.RESET_ALL}")
    return list(packets)


def parse_packet(pkt) -> dict:
    """
    Extract all relevant fields from a single packet into a dictionary.

    Args:
        pkt: A Scapy packet object

    Returns:
        Dictionary of parsed fields
    """
    info = {
        "timestamp": datetime.datetime.now().isoformat(),
        "size":      len(pkt),
        "proto":     "UNKNOWN",
        "src_ip":    None,
        "dst_ip":    None,
        "src_port":  None,
        "dst_port":  None,
        "ttl":       None,
        "flags":     None,
        "dns_query": None,
        "payload":   None,
    }

    if IP in pkt:
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst
        info["ttl"]    = pkt[IP].ttl

    if TCP in pkt:
        info["proto"]    = "TCP"
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport
        info["flags"]    = str(pkt[TCP].flags)

    elif UDP in pkt:
        info["proto"]    = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport

    elif ICMP in pkt:
        info["proto"] = "ICMP"

    elif ARP in pkt:
        info["proto"]  = "ARP"
        info["src_ip"] = pkt[ARP].psrc
        info["dst_ip"] = pkt[ARP].pdst

    if DNS in pkt and pkt[DNS].qd:
        try:
            info["dns_query"] = pkt[DNS].qd.qname.decode().rstrip(".")
        except Exception:
            pass

    if Raw in pkt:
        info["payload"] = bytes(pkt[Raw])[:100]

    return info
