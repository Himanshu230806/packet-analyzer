"""
demo.py — Demo Mode (No Admin Rights Required)
================================================
Creates a realistic synthetic packet capture and runs the full
analysis pipeline — so you can test and demonstrate the tool
without needing administrator/sudo privileges or a live network.

Run:
    python demo.py
"""

import os
import sys
from colorama import Fore, Style, init

init(autoreset=True)


def create_demo_packets():
    """
    Build a realistic set of synthetic Scapy packets that will
    trigger all of our detection modules.
    """
    from scapy.all import (
        IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
        Raw, Ether, wrpcap
    )

    packets = []

    # ── Normal HTTP traffic ────────────────────────────────────────────────
    for i in range(30):
        pkt = (IP(src=f"192.168.1.{10+i}", dst="93.184.216.34") /
               TCP(sport=1024+i, dport=80, flags="PA") /
               Raw(load=f"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        packets.append(pkt)

    # ── Cleartext credential in HTTP POST ─────────────────────────────────
    cred_payload = (
        b"POST /login HTTP/1.1\r\nHost: vulnerable-site.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"username=admin&password=SuperSecret123&login=Submit"
    )
    packets.append(
        IP(src="192.168.1.50", dst="10.10.10.5") /
        TCP(sport=54321, dport=80, flags="PA") /
        Raw(load=cred_payload)
    )

    # Another credential leak on FTP
    packets.append(
        IP(src="192.168.1.50", dst="10.10.10.6") /
        TCP(sport=54322, dport=21, flags="PA") /
        Raw(load=b"USER administrator\r\nPASS=MyFTPPassword!\r\n")
    )

    # ── SYN port scan (Nmap-style) ─────────────────────────────────────────
    scan_ports = [21,22,23,25,53,80,110,135,139,143,443,445,
                  1433,1521,3306,3389,5900,8080,8443,9200]
    for port in scan_ports:
        pkt = (IP(src="10.0.0.99", dst="192.168.1.1") /
               TCP(sport=60000, dport=port, flags="S"))
        packets.append(pkt)

    # ── ARP traffic (normal) ──────────────────────────────────────────────
    packets.append(
        Ether() /
        ARP(op=2, psrc="192.168.1.1",  hwsrc="aa:bb:cc:dd:ee:01",
            pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
    )
    packets.append(
        Ether() /
        ARP(op=2, psrc="192.168.1.5",  hwsrc="aa:bb:cc:dd:ee:02",
            pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
    )

    # ── ARP spoofing — same IP, different MAC ─────────────────────────────
    packets.append(
        Ether() /
        ARP(op=2, psrc="192.168.1.1",  hwsrc="de:ad:be:ef:00:01",
            pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
    )

    # ── DNS queries ────────────────────────────────────────────────────────
    normal_domains = [
        "google.com", "youtube.com", "github.com",
        "stackoverflow.com", "cloudflare.com",
        "amazon.com", "microsoft.com"
    ]
    for domain in normal_domains:
        for _ in range(3):
            pkt = (IP(src="192.168.1.10", dst="8.8.8.8") /
                   UDP(sport=53000, dport=53) /
                   DNS(rd=1, qd=DNSQR(qname=domain)))
            packets.append(pkt)

    # Suspicious DNS (DGA-like random domain)
    for domain in ["x7k2mq9p3n.xyz", "aabbccddee112233.top", "update-security-patch.tk"]:
        pkt = (IP(src="192.168.1.77", dst="8.8.8.8") /
               UDP(sport=53001, dport=53) /
               DNS(rd=1, qd=DNSQR(qname=domain)))
        packets.append(pkt)

    # High-frequency beaconing DNS (C2-like)
    for _ in range(60):
        pkt = (IP(src="192.168.1.77", dst="1.1.1.1") /
               UDP(sport=53002, dport=53) /
               DNS(rd=1, qd=DNSQR(qname="beacon.malicious-c2.xyz")))
        packets.append(pkt)

    # ── ICMP flood ─────────────────────────────────────────────────────────
    for _ in range(80):
        pkt = (IP(src="10.0.0.200", dst="192.168.1.1") /
               ICMP(type=8))
        packets.append(pkt)

    # ── Normal HTTPS traffic ───────────────────────────────────────────────
    for i in range(50):
        pkt = (IP(src=f"192.168.1.{20+i}", dst="142.250.80.46") /
               TCP(sport=2000+i, dport=443, flags="PA") /
               Raw(load=b"\x16\x03\x01" + os.urandom(40)))  # TLS record
        packets.append(pkt)

    # ── Normal UDP traffic ─────────────────────────────────────────────────
    for i in range(20):
        pkt = (IP(src=f"192.168.1.{30+i}", dst="8.8.8.8") /
               UDP(sport=5000+i, dport=53) /
               Raw(load=b"\x00\x01\x00\x00"))
        packets.append(pkt)

    return packets


def run_demo():
    print(f"""
{Fore.CYAN}{'═'*65}
  DEMO MODE — Network Packet Analyzer
  Generating synthetic capture & running full analysis...
{'═'*65}{Style.RESET_ALL}
""")

    # Create capture folder
    os.makedirs("captures", exist_ok=True)
    os.makedirs("reports",  exist_ok=True)

    # Generate packets
    print(f"{Fore.YELLOW}[*] Building synthetic packet capture...{Style.RESET_ALL}")
    packets = create_demo_packets()
    print(f"{Fore.GREEN}[+] Created {len(packets)} synthetic packets{Style.RESET_ALL}")

    # Save to pcap
    pcap_path = "captures/demo_capture.pcap"
    from scapy.all import wrpcap
    wrpcap(pcap_path, packets)
    print(f"{Fore.GREEN}[+] Saved demo capture: {Fore.CYAN}{pcap_path}{Style.RESET_ALL}")

    # Run analysis
    from analyzer import run_all_detections
    from report   import print_summary, export_csv, generate_html_report

    print(f"\n{Fore.CYAN}{'═'*65}")
    print(f"  RUNNING SECURITY ANALYSIS ON DEMO CAPTURE")
    print(f"{'═'*65}{Style.RESET_ALL}")

    findings, stats, dns_data = run_all_detections(packets)
    print_summary(findings, stats)

    csv_path  = export_csv(findings, stats, filename="reports/demo_findings.csv")
    html_path = generate_html_report(findings, stats, dns_data=dns_data,
                                     filename="reports/demo_report.html")

    print(f"""
{Fore.GREEN}{'═'*65}
  DEMO COMPLETE
{'═'*65}{Style.RESET_ALL}
  {Fore.CYAN}HTML report : {html_path}
  CSV export  : {csv_path}
  PCAP file   : {pcap_path}{Style.RESET_ALL}

  {Fore.YELLOW}Open {html_path} in your browser to see the full report.{Style.RESET_ALL}
  {Fore.YELLOW}Open {pcap_path} in Wireshark for packet-level inspection.{Style.RESET_ALL}
""")


if __name__ == "__main__":
    run_demo()
