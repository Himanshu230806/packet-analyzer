"""
analyzer.py — Packet Analysis & Threat Detection Module
========================================================
Runs multiple detection algorithms against captured packets:
  1. Cleartext credential detection (HTTP)
  2. SYN port scan detection
  3. ARP spoofing / MITM detection
  4. DNS query analysis & suspicious domain flagging
  5. ICMP flood detection
  6. Protocol distribution & top-talker statistics
"""

from collections import defaultdict, Counter
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
from colorama import Fore, Style, init
import re

init(autoreset=True)

# ─── Constants ─────────────────────────────────────────────────────────────

# Keywords that suggest credentials in HTTP payloads
CREDENTIAL_KEYWORDS = [
    b"password=", b"passwd=", b"pass=",
    b"username=", b"user=", b"email=",
    b"login=", b"pwd=", b"secret=",
    b"Authorization: Basic",
]

# Known suspicious / malware-associated TLDs and patterns
SUSPICIOUS_DOMAINS = [
    r"\.xyz$", r"\.top$", r"\.club$", r"\.tk$",
    r"[a-z0-9]{20,}\.",      # very long random subdomains (DGA)
    r"\d{5,}\.",             # many consecutive digits in domain
]

# Commonly targeted ports (for scan reporting)
WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
}


# ─── 1. Cleartext Credential Detection ─────────────────────────────────────

def detect_cleartext_credentials(packets: list) -> list:
    """
    Scan TCP port 80 payloads for credential-related keywords.
    HTTP sends everything in plaintext — this proves why HTTPS matters.

    Returns:
        List of finding dicts with keys: type, severity, src_ip, dst_ip,
        dst_port, keyword, raw_payload_preview
    """
    findings = []
    print(f"\n{Fore.CYAN}[*] Checking for cleartext credentials...{Style.RESET_ALL}")

    for pkt in packets:
        if IP not in pkt or TCP not in pkt or Raw not in pkt:
            continue

        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        # Only inspect HTTP traffic (port 80) or other non-encrypted ports
        if dport not in (80, 8080, 21, 110, 143, 23) and sport not in (80, 8080):
            continue

        payload = bytes(pkt[Raw]).lower()

        for kw in CREDENTIAL_KEYWORDS:
            if kw.lower() in payload:
                preview = bytes(pkt[Raw])[:200].decode("utf-8", errors="replace")
                finding = {
                    "type":            "Cleartext Credential Exposure",
                    "severity":        "HIGH",
                    "src_ip":          pkt[IP].src,
                    "dst_ip":          pkt[IP].dst,
                    "dst_port":        dport,
                    "service":         WELL_KNOWN_PORTS.get(dport, str(dport)),
                    "keyword":         kw.decode("utf-8", errors="replace"),
                    "payload_preview": preview,
                    "recommendation":  "Use HTTPS/TLS for all authentication. Never send credentials over HTTP.",
                }
                findings.append(finding)
                print(f"  {Fore.RED}[HIGH]{Style.RESET_ALL} Cleartext credential found: "
                      f"{pkt[IP].src} → {pkt[IP].dst}:{dport} "
                      f"  keyword='{kw.decode()}'")
                break  # one finding per packet

    if not findings:
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} No cleartext credentials detected.")

    return findings


# ─── 2. Port Scan Detection ─────────────────────────────────────────────────

def detect_port_scan(packets: list, threshold: int = 15) -> list:
    """
    Detect SYN-only port scanning (Nmap -sS style).
    A scanner sends SYN packets to many ports without completing the handshake.

    Args:
        threshold: Minimum distinct ports probed to trigger an alert

    Returns:
        List of finding dicts
    """
    findings = []
    syn_map  = defaultdict(set)   # src_ip → {dst_ports}
    syn_targets = defaultdict(set) # src_ip → {dst_ips}

    print(f"\n{Fore.CYAN}[*] Checking for port scans...{Style.RESET_ALL}")

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue

        flags = str(pkt[TCP].flags)
        # SYN-only (no ACK) = scan probe, not a legitimate connection
        if "S" in flags and "A" not in flags:
            src = pkt[IP].src
            syn_map[src].add(pkt[TCP].dport)
            syn_targets[src].add(pkt[IP].dst)

    for src_ip, ports in syn_map.items():
        if len(ports) >= threshold:
            named_ports = {p: WELL_KNOWN_PORTS.get(p, "unknown") for p in sorted(ports)[:20]}
            finding = {
                "type":          "Port Scan Detected",
                "severity":      "MEDIUM",
                "src_ip":        src_ip,
                "targets":       list(syn_targets[src_ip]),
                "ports_probed":  len(ports),
                "port_list":     sorted(ports)[:30],
                "named_ports":   named_ports,
                "recommendation": "Block the source IP at the firewall. Investigate if this is an internal scanner.",
            }
            findings.append(finding)
            print(f"  {Fore.YELLOW}[MEDIUM]{Style.RESET_ALL} Port scan from {Fore.YELLOW}{src_ip}{Style.RESET_ALL} "
                  f"— {len(ports)} ports probed  "
                  f"({', '.join([f'{p}/{WELL_KNOWN_PORTS.get(p,str(p))}' for p in sorted(ports)[:5]])}...)")

    if not findings:
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} No port scans detected.")

    return findings


# ─── 3. ARP Spoofing Detection ──────────────────────────────────────────────

def detect_arp_spoofing(packets: list) -> list:
    """
    Detect ARP cache poisoning (Man-in-the-Middle attacks).
    Watches for IP addresses that change their associated MAC address mid-capture.

    Returns:
        List of finding dicts
    """
    findings  = []
    ip_mac_map = {}   # ip → mac (first seen)

    print(f"\n{Fore.CYAN}[*] Checking for ARP spoofing...{Style.RESET_ALL}")

    for pkt in packets:
        if ARP not in pkt:
            continue

        if pkt[ARP].op != 2:   # 2 = ARP reply (is-at)
            continue

        ip  = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        if ip in ip_mac_map:
            if ip_mac_map[ip] != mac:
                finding = {
                    "type":         "ARP Spoofing / MITM Attack",
                    "severity":     "HIGH",
                    "ip":           ip,
                    "original_mac": ip_mac_map[ip],
                    "spoofed_mac":  mac,
                    "recommendation": (
                        "Enable Dynamic ARP Inspection (DAI) on your switch. "
                        "Use static ARP entries for critical hosts."
                    ),
                }
                findings.append(finding)
                print(f"  {Fore.RED}[HIGH]{Style.RESET_ALL} ARP spoofing! IP {Fore.YELLOW}{ip}{Style.RESET_ALL} "
                      f"changed MAC: {ip_mac_map[ip]} → {Fore.RED}{mac}{Style.RESET_ALL}")
        else:
            ip_mac_map[ip] = mac

    if not findings:
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} No ARP spoofing detected.")

    return findings


# ─── 4. DNS Analysis ────────────────────────────────────────────────────────

def analyze_dns(packets: list) -> tuple:
    """
    Extract and analyse all DNS queries.
    Flags suspicious domains: DGA patterns, unusual TLDs, high-frequency beaconing.

    Returns:
        (queries list, frequency Counter, suspicious_findings list)
    """
    queries     = []
    suspicious  = []

    print(f"\n{Fore.CYAN}[*] Analysing DNS queries...{Style.RESET_ALL}")

    for pkt in packets:
        if DNS not in pkt:
            continue
        if not pkt[DNS].qd:
            continue

        try:
            domain = pkt[DNS].qd.qname.decode().rstrip(".")
            queries.append(domain)
        except Exception:
            continue

    freq = Counter(queries)

    # Flag suspicious domains
    for domain in set(queries):
        reasons = []
        for pattern in SUSPICIOUS_DOMAINS:
            if re.search(pattern, domain, re.IGNORECASE):
                reasons.append(f"matches pattern: {pattern}")

        if freq[domain] > 50:
            reasons.append(f"high query frequency ({freq[domain]}x) — possible beaconing")

        if reasons:
            suspicious.append({
                "type":           "Suspicious DNS Query",
                "severity":       "MEDIUM",
                "domain":         domain,
                "query_count":    freq[domain],
                "reasons":        reasons,
                "recommendation": "Investigate this domain. Consider blocking at DNS level.",
            })
            print(f"  {Fore.YELLOW}[MEDIUM]{Style.RESET_ALL} Suspicious domain: "
                  f"{Fore.YELLOW}{domain}{Style.RESET_ALL}  ({', '.join(reasons)})")

    # Print top 10 domains
    if freq:
        print(f"\n  {'─'*50}")
        print(f"  {'Top DNS Queries':}")
        print(f"  {'─'*50}")
        for domain, count in freq.most_common(10):
            bar = "█" * min(count, 30)
            print(f"  {count:5d}x  {domain:<40} {Fore.CYAN}{bar}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.WHITE}No DNS queries found in capture.{Style.RESET_ALL}")

    return queries, freq, suspicious


# ─── 5. ICMP Flood Detection ─────────────────────────────────────────────────

def detect_icmp_flood(packets: list, threshold: int = 50) -> list:
    """
    Detect ICMP (ping) floods — a basic DoS technique.

    Args:
        threshold: ICMP packets from one source to trigger an alert

    Returns:
        List of finding dicts
    """
    findings  = []
    icmp_count = defaultdict(int)

    print(f"\n{Fore.CYAN}[*] Checking for ICMP floods...{Style.RESET_ALL}")

    for pkt in packets:
        if IP in pkt and ICMP in pkt:
            icmp_count[pkt[IP].src] += 1

    for src_ip, count in icmp_count.items():
        if count >= threshold:
            finding = {
                "type":           "ICMP Flood (DoS)",
                "severity":       "MEDIUM",
                "src_ip":         src_ip,
                "icmp_count":     count,
                "recommendation": "Rate-limit ICMP at the firewall. Block the source if malicious.",
            }
            findings.append(finding)
            print(f"  {Fore.YELLOW}[MEDIUM]{Style.RESET_ALL} ICMP flood from {Fore.YELLOW}{src_ip}{Style.RESET_ALL} "
                  f"— {count} ICMP packets")

    if not findings:
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} No ICMP floods detected.")

    return findings


# ─── 6. Traffic Statistics ───────────────────────────────────────────────────

def traffic_stats(packets: list) -> dict:
    """
    Compute overall traffic statistics:
    - Protocol distribution
    - Top talkers (by bytes sent)
    - Top destination ports
    - Packet size distribution

    Returns:
        Dictionary with stats keys
    """
    protocols    = Counter()
    top_talkers  = defaultdict(int)   # src_ip → bytes
    top_dest_ips = defaultdict(int)   # dst_ip → packet count
    top_ports    = defaultdict(int)   # dst_port → count
    pkt_sizes    = []

    print(f"\n{Fore.CYAN}[*] Computing traffic statistics...{Style.RESET_ALL}")

    for pkt in packets:
        size = len(pkt)
        pkt_sizes.append(size)

        if IP in pkt:
            top_talkers[pkt[IP].src]   += size
            top_dest_ips[pkt[IP].dst]  += 1

            if TCP in pkt:
                protocols["TCP"] += 1
                top_ports[pkt[TCP].dport] += 1
            elif UDP in pkt:
                protocols["UDP"] += 1
                top_ports[pkt[UDP].dport] += 1
            elif ICMP in pkt:
                protocols["ICMP"] += 1
            else:
                protocols["Other-IP"] += 1
        elif ARP in pkt:
            protocols["ARP"] += 1
        else:
            protocols["Non-IP"] += 1

    total = len(packets)
    avg_size = round(sum(pkt_sizes) / total, 1) if total else 0
    total_bytes = sum(pkt_sizes)

    # Print summary
    print(f"\n  {'─'*55}")
    print(f"  {'TRAFFIC SUMMARY':}")
    print(f"  {'─'*55}")
    print(f"  Total packets : {total:,}")
    print(f"  Total bytes   : {total_bytes:,} ({total_bytes/1024:.1f} KB)")
    print(f"  Avg pkt size  : {avg_size} bytes")

    print(f"\n  {'Protocol':<12} {'Count':>8} {'%':>6}")
    print(f"  {'─'*30}")
    for proto, count in protocols.most_common():
        pct = (count / total * 100) if total else 0
        print(f"  {proto:<12} {count:>8,} {pct:>5.1f}%")

    print(f"\n  Top Talkers (by bytes):")
    for ip, b in sorted(top_talkers.items(), key=lambda x: -x[1])[:5]:
        print(f"  {ip:<20} {b:>10,} bytes")

    print(f"\n  Top Destination Ports:")
    for port, count in Counter(top_ports).most_common(8):
        service = WELL_KNOWN_PORTS.get(port, "unknown")
        print(f"  {port:<6} ({service:<10}) {count:>6} packets")

    return {
        "total_packets":  total,
        "total_bytes":    total_bytes,
        "avg_packet_size": avg_size,
        "protocols":      dict(protocols),
        "top_talkers":    dict(sorted(top_talkers.items(), key=lambda x: -x[1])[:10]),
        "top_dest_ips":   dict(sorted(top_dest_ips.items(), key=lambda x: -x[1])[:10]),
        "top_ports":      dict(Counter(top_ports).most_common(10)),
    }


# ─── Run All Detections ──────────────────────────────────────────────────────

def run_all_detections(packets: list) -> tuple:
    """
    Run every detection module and return combined findings + stats.

    Returns:
        (all_findings list, stats dict, dns_data tuple)
    """
    all_findings = []

    all_findings += detect_cleartext_credentials(packets)
    all_findings += detect_port_scan(packets)
    all_findings += detect_arp_spoofing(packets)
    all_findings += detect_icmp_flood(packets)

    dns_queries, dns_freq, dns_findings = analyze_dns(packets)
    all_findings += dns_findings

    stats = traffic_stats(packets)

    return all_findings, stats, (dns_queries, dns_freq)
