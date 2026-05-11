"""
main.py — Network Packet Analyzer — Entry Point
=================================================
Usage:
  # Live capture (needs administrator / sudo):
  sudo python main.py --iface eth0 --count 300

  # Analyse an existing .pcap file (no admin needed):
  python main.py --load captures/capture.pcap

  # Show network interfaces:
  python main.py --list-interfaces

  # Custom output filename:
  python main.py --load sample.pcap --report-name my_report

Author : Your Name
Project: Network Packet Analyzer (Cybersecurity Portfolio)
"""

import argparse
import sys
import os
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
  ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
         PACKET ANALYZER v1.0  |  Cybersecurity Portfolio Project
{Style.RESET_ALL}"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer — capture, parse, and detect threats",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python main.py --list-interfaces
  sudo python main.py --iface eth0 --count 500
  python main.py --load captures/capture.pcap
  python main.py --load captures/capture.pcap --report-name pentest_lab
        """
    )
    parser.add_argument(
        "--iface", "-i",
        default=None,
        help="Network interface to capture on (e.g. eth0, Wi-Fi)"
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=200,
        help="Number of packets to capture (default: 200, 0 = unlimited)"
    )
    parser.add_argument(
        "--load", "-l",
        default=None,
        help="Path to an existing .pcap file to analyse offline"
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List all available network interfaces and exit"
    )
    parser.add_argument(
        "--report-name",
        default=None,
        help="Base name for output report files (default: auto-timestamped)"
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip generating the HTML report"
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Skip generating the CSV export"
    )
    return parser.parse_args()


def main():
    print(BANNER)

    args = parse_args()

    # Lazy imports so --list-interfaces works without full scapy init
    from capture  import list_interfaces, start_capture, load_capture
    from analyzer import run_all_detections
    from report   import print_summary, export_csv, generate_html_report

    # ── List interfaces & exit ─────────────────────────────────────────────
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # ── Load or capture packets ────────────────────────────────────────────
    if args.load:
        if not os.path.exists(args.load):
            print(f"{Fore.RED}[!] File not found: {args.load}{Style.RESET_ALL}")
            sys.exit(1)
        packets = load_capture(args.load)
    else:
        if args.iface is None:
            print(f"{Fore.YELLOW}[!] No interface specified. Listing interfaces...{Style.RESET_ALL}")
            ifaces = list_interfaces()
            print(f"{Fore.CYAN}Use: python main.py --iface <interface_name>{Style.RESET_ALL}")
            sys.exit(0)
        packets = start_capture(interface=args.iface, count=args.count, save=True)

    if not packets:
        print(f"{Fore.RED}[!] No packets to analyse. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

    # ── Run all detections ─────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'═'*65}")
    print(f"  RUNNING SECURITY ANALYSIS")
    print(f"{'═'*65}{Style.RESET_ALL}")

    findings, stats, dns_data = run_all_detections(packets)

    # ── Terminal summary ───────────────────────────────────────────────────
    print_summary(findings, stats)

    # ── CSV export ─────────────────────────────────────────────────────────
    csv_path = None
    if not args.no_csv:
        csv_name = f"reports/{args.report_name}.csv" if args.report_name else None
        csv_path = export_csv(findings, stats, filename=csv_name)

    # ── HTML report ────────────────────────────────────────────────────────
    html_path = None
    if not args.no_html:
        html_name = f"reports/{args.report_name}.html" if args.report_name else None
        html_path = generate_html_report(findings, stats, dns_data=dns_data, filename=html_name)

    # ── Done ───────────────────────────────────────────────────────────────
    print(f"\n{Fore.GREEN}{'═'*65}")
    print(f"  ANALYSIS COMPLETE")
    print(f"{'═'*65}{Style.RESET_ALL}")
    if html_path:
        print(f"  {Fore.CYAN}HTML report : {html_path}{Style.RESET_ALL}")
    if csv_path:
        print(f"  {Fore.CYAN}CSV export  : {csv_path}{Style.RESET_ALL}")
    print(f"\n  Open the HTML report in your browser to view the full results.\n")


if __name__ == "__main__":
    main()
