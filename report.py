"""
report.py — Report Generation Module
======================================
Generates three output formats from analysis findings:
  1. Pretty terminal summary (colored)
  2. CSV export (all findings as rows)
  3. Full HTML report (professional, shareable)
"""

import csv
import json
import datetime
import os
from colorama import Fore, Style, init

init(autoreset=True)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SEVERITY_COLOR = {
    "HIGH":   "#c0392b",
    "MEDIUM": "#e67e22",
    "LOW":    "#27ae60",
    "INFO":   "#2980b9",
}


# ─── Terminal Summary ────────────────────────────────────────────────────────

def print_summary(findings: list, stats: dict):
    """Print a formatted summary to the terminal."""
    total   = len(findings)
    high    = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium  = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low     = sum(1 for f in findings if f.get("severity") == "LOW")

    print(f"\n{'═'*65}")
    print(f"  ANALYSIS COMPLETE")
    print(f"{'═'*65}")
    print(f"  Packets analysed : {stats.get('total_packets', 0):,}")
    print(f"  Total bytes      : {stats.get('total_bytes', 0):,}")
    print(f"  Findings         : {total} total")
    print(f"    {Fore.RED}HIGH   : {high}{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}MEDIUM : {medium}{Style.RESET_ALL}")
    print(f"    {Fore.GREEN}LOW    : {low}{Style.RESET_ALL}")
    print(f"{'═'*65}\n")

    if findings:
        print(f"  {'Severity':<8}  {'Type':<35}  {'Source IP'}")
        print(f"  {'─'*65}")
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "LOW"), 3)):
            sev   = f.get("severity", "INFO")
            ftype = f.get("type", "Unknown")[:34]
            src   = f.get("src_ip") or f.get("ip", "N/A")
            color = Fore.RED if sev == "HIGH" else Fore.YELLOW if sev == "MEDIUM" else Fore.GREEN
            print(f"  {color}{sev:<8}{Style.RESET_ALL}  {ftype:<35}  {src}")
    else:
        print(f"  {Fore.GREEN}No security findings — traffic looks clean.{Style.RESET_ALL}")

    print()


# ─── CSV Export ─────────────────────────────────────────────────────────────

def export_csv(findings: list, stats: dict, filename: str = None) -> str:
    """
    Export findings to a CSV file.

    Returns:
        Path to the saved CSV file
    """
    os.makedirs("reports", exist_ok=True)
    if not filename:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/findings_{ts}.csv"

    if not findings:
        print(f"{Fore.YELLOW}[!] No findings to export to CSV.{Style.RESET_ALL}")
        return filename

    # Flatten all findings to a flat dict (some have nested lists)
    flat_rows = []
    for f in findings:
        row = {}
        for k, v in f.items():
            if isinstance(v, (list, dict)):
                row[k] = json.dumps(v)
            elif isinstance(v, bytes):
                row[k] = v.decode("utf-8", errors="replace")
            else:
                row[k] = v
        flat_rows.append(row)

    # Collect all unique keys
    all_keys = []
    for row in flat_rows:
        for k in row.keys():
            if k not in all_keys:
                all_keys.append(k)

    with open(filename, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flat_rows)

    print(f"{Fore.GREEN}[+] CSV report saved: {Fore.CYAN}{filename}{Style.RESET_ALL}")
    return filename


# ─── HTML Report ─────────────────────────────────────────────────────────────

def generate_html_report(findings: list, stats: dict,
                         dns_data: tuple = None, filename: str = None) -> str:
    """
    Generate a professional, self-contained HTML report.

    Args:
        findings : List of finding dicts from analyzer.py
        stats    : Traffic statistics dict from analyzer.py
        dns_data : (queries list, Counter) from analyze_dns()
        filename : Output file path (auto-generated if None)

    Returns:
        Path to the saved HTML file
    """
    os.makedirs("reports", exist_ok=True)
    if not filename:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/report_{ts}.html"

    now     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total   = len(findings)
    high    = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium  = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low     = sum(1 for f in findings if f.get("severity") == "LOW")

    # Build protocol chart data
    protocols = stats.get("protocols", {})
    proto_labels  = list(protocols.keys())
    proto_values  = list(protocols.values())
    proto_colors  = ["#3498db","#2ecc71","#e74c3c","#f39c12","#9b59b6","#1abc9c"]

    # Build top talkers rows
    talker_rows = ""
    for ip, b in stats.get("top_talkers", {}).items():
        talker_rows += f"<tr><td>{ip}</td><td>{b:,}</td><td>{b/1024:.1f} KB</td></tr>\n"

    # Build top ports rows
    port_rows = ""
    from analyzer import WELL_KNOWN_PORTS
    for port, count in stats.get("top_ports", {}).items():
        svc = WELL_KNOWN_PORTS.get(int(port), "unknown")
        port_rows += f"<tr><td>{port}</td><td>{svc}</td><td>{count:,}</td></tr>\n"

    # Build DNS top queries rows
    dns_rows = ""
    if dns_data:
        _, dns_freq = dns_data
        for domain, count in dns_freq.most_common(15):
            dns_rows += f"<tr><td>{domain}</td><td>{count}</td></tr>\n"

    # Build findings cards
    findings_html = ""
    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity","LOW"), 3))
    for idx, f in enumerate(sorted_findings, 1):
        sev   = f.get("severity", "INFO")
        ftype = f.get("type", "Unknown")
        src   = f.get("src_ip") or f.get("ip", "N/A")
        dst   = f.get("dst_ip", "N/A")
        rec   = f.get("recommendation", "")
        color = SEVERITY_COLOR.get(sev, "#888")

        detail_rows = ""
        skip_keys   = {"type", "severity", "recommendation", "payload_preview"}
        for k, v in f.items():
            if k in skip_keys:
                continue
            if isinstance(v, (list, dict)):
                v = json.dumps(v, indent=2)
            elif isinstance(v, bytes):
                v = v.decode("utf-8", errors="replace")
            detail_rows += f"<tr><td class='dk'>{k}</td><td>{str(v)[:300]}</td></tr>"

        payload_section = ""
        if "payload_preview" in f:
            payload_section = f"""
            <div class="payload-box">
              <span class="pl-label">Payload preview:</span>
              <code>{f['payload_preview'][:300]}</code>
            </div>"""

        findings_html += f"""
        <div class="finding-card" id="finding-{idx}">
          <div class="finding-header" style="border-left: 4px solid {color}">
            <div>
              <span class="sev-badge" style="background:{color}">{sev}</span>
              <span class="finding-title">{ftype}</span>
            </div>
            <span class="finding-num">#{idx}</span>
          </div>
          <div class="finding-body">
            <table class="detail-table">{detail_rows}</table>
            {payload_section}
            <div class="rec-box">
              <i>&#128736;</i> <strong>Recommendation:</strong> {rec}
            </div>
          </div>
        </div>"""

    no_findings_msg = ""
    if not findings:
        no_findings_msg = '<div class="clean-box">&#10003; No security findings detected — traffic appears clean.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Packet Analysis Report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e0e0e0; line-height: 1.6; }}
  a {{ color: #4fc3f7; }}

  /* Header */
  .header {{ background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%);
             padding: 40px; color: white; }}
  .header h1 {{ font-size: 28px; font-weight: 600; margin-bottom: 4px; }}
  .header p  {{ opacity: .75; font-size: 14px; }}
  .header-meta {{ display: flex; gap: 24px; margin-top: 16px; flex-wrap: wrap; }}
  .meta-item {{ font-size: 13px; opacity: .85; }}
  .meta-item strong {{ display: block; font-size: 11px; opacity: .7; text-transform: uppercase; letter-spacing: .05em; }}

  /* Layout */
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}
  .section {{ margin-bottom: 40px; }}
  .section-title {{ font-size: 18px; font-weight: 600; color: #90caf9;
                    border-bottom: 1px solid #1e3a5f; padding-bottom: 8px; margin-bottom: 20px; }}

  /* Stat cards */
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
  .stat-card {{ background: #1e1e2e; border: 1px solid #2a2a3e; border-radius: 10px;
                padding: 16px; text-align: center; }}
  .stat-card .val {{ font-size: 28px; font-weight: 700; margin-bottom: 4px; }}
  .stat-card .lbl {{ font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: .05em; }}
  .c-red    {{ color: #ef5350; }}
  .c-orange {{ color: #ffa726; }}
  .c-green  {{ color: #66bb6a; }}
  .c-blue   {{ color: #42a5f5; }}
  .c-white  {{ color: #e0e0e0; }}

  /* Charts */
  .chart-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  @media (max-width: 700px) {{ .chart-grid {{ grid-template-columns: 1fr; }} }}
  .chart-box {{ background: #1e1e2e; border: 1px solid #2a2a3e; border-radius: 10px; padding: 20px; }}
  .chart-box h3 {{ font-size: 14px; color: #90caf9; margin-bottom: 16px; }}

  /* Tables */
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #1a237e; color: white; padding: 8px 12px; text-align: left; font-weight: 500; }}
  td {{ padding: 7px 12px; border-bottom: 1px solid #1e1e2e; }}
  tr:hover td {{ background: #1e1e2e; }}
  .tbl-box {{ background: #161625; border: 1px solid #2a2a3e; border-radius: 10px; overflow: hidden; }}

  /* Findings */
  .finding-card {{ background: #161625; border: 1px solid #2a2a3e; border-radius: 10px;
                   margin-bottom: 16px; overflow: hidden; }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: center;
                     padding: 14px 18px; background: #1e1e2e; }}
  .sev-badge {{ font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 4px;
                color: white; margin-right: 10px; letter-spacing: .05em; }}
  .finding-title {{ font-size: 15px; font-weight: 500; }}
  .finding-num {{ font-size: 12px; color: #555; }}
  .finding-body {{ padding: 16px 18px; }}
  .detail-table td {{ font-size: 12px; padding: 4px 8px; border-bottom: 1px solid #1e1e2e; }}
  .detail-table .dk {{ color: #888; width: 140px; white-space: nowrap; }}
  .payload-box {{ background: #0a0a14; border: 1px solid #2a2a3e; border-radius: 6px;
                  padding: 10px 12px; margin: 12px 0; font-size: 12px; overflow-x: auto; }}
  .payload-box .pl-label {{ color: #888; display: block; margin-bottom: 4px; font-size: 11px; }}
  .payload-box code {{ color: #80cbc4; white-space: pre-wrap; word-break: break-all; }}
  .rec-box {{ background: #1a2a1a; border-left: 3px solid #66bb6a; padding: 10px 14px;
              border-radius: 0 6px 6px 0; font-size: 13px; margin-top: 12px; color: #a5d6a7; }}
  .clean-box {{ background: #1a2a1a; border: 1px solid #66bb6a; border-radius: 10px;
                padding: 24px; text-align: center; color: #66bb6a; font-size: 16px; }}

  /* Footer */
  .footer {{ text-align: center; padding: 32px; color: #444; font-size: 12px; border-top: 1px solid #1e1e2e; }}
</style>
</head>
<body>

<div class="header">
  <h1>&#128270; Network Packet Analysis Report</h1>
  <p>Security findings and traffic analysis from packet capture</p>
  <div class="header-meta">
    <div class="meta-item"><strong>Generated</strong>{now}</div>
    <div class="meta-item"><strong>Total Packets</strong>{stats.get('total_packets',0):,}</div>
    <div class="meta-item"><strong>Total Data</strong>{stats.get('total_bytes',0)/1024:.1f} KB</div>
    <div class="meta-item"><strong>Findings</strong>{total} ({high} HIGH, {medium} MEDIUM)</div>
  </div>
</div>

<div class="container">

  <!-- Executive Summary -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="stat-grid">
      <div class="stat-card"><div class="val c-white">{stats.get('total_packets',0):,}</div><div class="lbl">Packets Captured</div></div>
      <div class="stat-card"><div class="val c-white">{stats.get('total_bytes',0)/1024:.1f}KB</div><div class="lbl">Data Analysed</div></div>
      <div class="stat-card"><div class="val c-white">{total}</div><div class="lbl">Total Findings</div></div>
      <div class="stat-card"><div class="val c-red">{high}</div><div class="lbl">High Severity</div></div>
      <div class="stat-card"><div class="val c-orange">{medium}</div><div class="lbl">Medium Severity</div></div>
      <div class="stat-card"><div class="val c-green">{low}</div><div class="lbl">Low Severity</div></div>
    </div>
  </div>

  <!-- Charts -->
  <div class="section">
    <div class="section-title">Traffic Overview</div>
    <div class="chart-grid">
      <div class="chart-box">
        <h3>Protocol Distribution</h3>
        <canvas id="protoChart" height="200"></canvas>
      </div>
      <div class="chart-box">
        <h3>Findings by Severity</h3>
        <canvas id="sevChart" height="200"></canvas>
      </div>
    </div>
  </div>

  <!-- Top Talkers -->
  <div class="section">
    <div class="section-title">Top Talkers</div>
    <div class="tbl-box">
      <table>
        <thead><tr><th>IP Address</th><th>Bytes Sent</th><th>Volume</th></tr></thead>
        <tbody>{talker_rows or '<tr><td colspan="3" style="text-align:center;color:#555">No IP traffic captured</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <!-- Top Ports -->
  <div class="section">
    <div class="section-title">Top Destination Ports</div>
    <div class="tbl-box">
      <table>
        <thead><tr><th>Port</th><th>Service</th><th>Packet Count</th></tr></thead>
        <tbody>{port_rows or '<tr><td colspan="3" style="text-align:center;color:#555">No port data</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <!-- DNS -->
  <div class="section">
    <div class="section-title">DNS Query Analysis</div>
    <div class="tbl-box">
      <table>
        <thead><tr><th>Domain</th><th>Query Count</th></tr></thead>
        <tbody>{dns_rows or '<tr><td colspan="2" style="text-align:center;color:#555">No DNS queries captured</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <!-- Findings -->
  <div class="section">
    <div class="section-title">Security Findings ({total})</div>
    {findings_html}
    {no_findings_msg}
  </div>

</div>

<div class="footer">
  Generated by Network Packet Analyzer &nbsp;|&nbsp; For educational use only &nbsp;|&nbsp; {now}
</div>

<script>
// Protocol chart
new Chart(document.getElementById('protoChart'), {{
  type: 'doughnut',
  data: {{
    labels: {json.dumps(proto_labels)},
    datasets: [{{
      data: {json.dumps(proto_values)},
      backgroundColor: {json.dumps(proto_colors[:len(proto_labels)])},
      borderColor: '#1e1e2e',
      borderWidth: 2,
    }}]
  }},
  options: {{
    plugins: {{
      legend: {{ labels: {{ color: '#ccc', font: {{ size: 12 }} }} }}
    }}
  }}
}});

// Severity chart
new Chart(document.getElementById('sevChart'), {{
  type: 'bar',
  data: {{
    labels: ['HIGH', 'MEDIUM', 'LOW'],
    datasets: [{{
      label: 'Findings',
      data: [{high}, {medium}, {low}],
      backgroundColor: ['#ef5350', '#ffa726', '#66bb6a'],
      borderRadius: 6,
    }}]
  }},
  options: {{
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#aaa' }}, grid: {{ color: '#2a2a3e' }} }},
      y: {{ ticks: {{ color: '#aaa', stepSize: 1 }}, grid: {{ color: '#2a2a3e' }} }}
    }}
  }}
}});
</script>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"{Fore.GREEN}[+] HTML report saved: {Fore.CYAN}{filename}{Style.RESET_ALL}")
    return filename
