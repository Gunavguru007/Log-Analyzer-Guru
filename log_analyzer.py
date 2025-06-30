#!/usr/bin/env python3
"""
log_analyzer.py - Comprehensive Log Analysis Dashboard and CLI Tool
"""

import os
import re
import sys
import glob
import json
import csv
import argparse
import base64
import tempfile
import subprocess
from datetime import datetime, timezone
from collections import deque, Counter
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from io import StringIO, BytesIO

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.io as pio
from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader, select_autoescape
from tqdm import tqdm
from colorama import Fore, init

# Optional imports for Streamlit
try:
    import streamlit as st
    IS_STREAMLIT = True
except ImportError:
    IS_STREAMLIT = False

# Initialize colorama for CLI
init(autoreset=True)

# ================== DATA MODELS ==================

@dataclass
class XRLogEntry:
    log_id: str
    timestamp: int
    event_type: str
    action: str
    target_type: str
    target: str
    file_path: Optional[str]
    raw: str

# ================== CONSTANTS & RULES ==================

CORPORATE_CLASSIFICATION_RULES = {
    'Authentication': [
        r'XR-LOG!@OPN_usr',
        r'XR-LOG!@CLS_usr'
    ],
    'Process': [
        r'XR-EXEC!@RUN',
        r'XR-SHDW!@KILL_proc'
    ],
    'File': [
        r'XR-FILE!@MOD',
        r'XR-DEL!@DEL'
    ],
    'Network': [
        r'XR-CONN!@IP',
        r'XR-PORT!@'
    ],
    'Security': [
        r'XR-SHDW!@',
        r'XR-ALERT!@'
    ],
    'System': [
        r'XR-SYS!@',
        r'XR-BOOT!@'
    ]
}

SUSPICIOUS_RULES = {
    "Shadow Copy + Process Kill": [
        r"vssadmin\s+create\s+shadow",
        r"(taskkill|process deleted)"
    ],
    "User Escalation": [
        r"net localgroup administrators",
        r"runas"
    ],
    "Unexpected File Deletion": [
        r"deleted.*\.(log|bak|shadow)",
        r"file.*deleted.*(system32|windows)"
    ],
    "Unusual Port Usage": [
        r"port=(6[0-5]{1}[0-5]{2}[0-9]{1}|4915[2-9]|491[6-9][0-9]|49[2-9][0-9]{2}|[5-9][0-9]{4})"
    ],
    "Persistence Behavior": [
        r"reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ],
    "Security Tools Disabled": [
        r"(defender off|AV disabled|firewall disable)"
    ],
    "Exfiltration Suspicion": [
        r"(zip|compressed).*external IP",
        r"(upload|transferred).*http[s]?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3})(?::[0-9]+)?"
    ],
    "Unusual Login Time": [],
    "Multiple Failed Logins": []
}

SENSITIVE_FILES = ['/etc/passwd', '/bin/xz', '/usr/lib/xrun.conf']

# ================== PARSING FUNCTIONS ==================

class XRLogParser:
    def __init__(self):
        self.pattern = r'^(0x[0-9A-F]+)\[ts:(\d+)\]\|EVNT:(XR-[A-Z]+)!@([A-Z]+)_([^:]+):([^\s=>]+)(?:=>([^\s]+))?'
    
    def parse_line(self, line: str) -> Tuple[Optional[XRLogEntry], Optional[str]]:
        try:
            line = line.strip()
            if not line or "!!MALFORMED!!" in line:
                return None, "Malformed line"
            
            match = re.match(self.pattern, line)
            if not match:
                return None, "Pattern mismatch"
            
            return XRLogEntry(
                log_id=match.group(1),
                timestamp=int(match.group(2)),
                event_type=match.group(3),
                action=match.group(4),
                target_type=match.group(5),
                target=match.group(6),
                file_path=match.group(7) if match.group(7) else None,
                raw=line
            ), None
            
        except Exception as e:
            return None, f"Error parsing line: {str(e)}"

def parse_logs(logdir_or_files):
    """Parse logs from .log, .txt, .csv files in directory or list of files."""
    if isinstance(logdir_or_files, str):
        files = glob.glob(os.path.join(logdir_or_files, "*.[lL][oO][gG]")) + \
                glob.glob(os.path.join(logdir_or_files, "*.[tT][xX][tT]")) + \
                glob.glob(os.path.join(logdir_or_files, "*.[cC][sS][vV]"))
    else:
        files = logdir_or_files
    
    log_data = []
    parser = XRLogParser()
    
    for file in tqdm(files, desc="Parsing Files"):
        try:
            if isinstance(file, str):
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            else:
                # Handle file upload objects
                lines = file.read().decode('utf-8').splitlines()
        except Exception as e:
            print(f"[!] Error reading {file}: {e}")
            continue
        
        for line in lines:
            # Try XR log format first
            entry, error = parser.parse_line(line)
            if entry:
                log_data.append(entry.__dict__)
                continue
                
            # Fall back to generic parsing
            entry = {
                "timestamp": None,
                "actor": "",
                "action": "",
                "target": "",
                "event_type": "",
                "source_file": os.path.basename(file) if isinstance(file, str) else file.name,
                "raw": line.strip()
            }
            
            # Parse [ts:1234567] style timestamps
            ts_match = re.search(r'\[ts:(\d+)\]', line)
            if ts_match:
                try:
                    epoch = int(ts_match.group(1))
                    dt = datetime.fromtimestamp(epoch, timezone.utc)
                    entry["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
            
            # Extract actor, action, and target
            evnt_match = re.search(r'EVNT:([^!]+)!@([^_]+)_usr:([^=>]+)=>(.*)', line)
            if evnt_match:
                event_type = evnt_match.group(1)
                action = evnt_match.group(2)
                actor = evnt_match.group(3)
                target = evnt_match.group(4).strip()
                
                entry["actor"] = str(actor) if actor else ""
                entry["action"] = str(action) if action else ""
                entry["target"] = str(target) if target else ""
                entry["event_type"] = str(event_type) if event_type else ""
            
            # Add entry only if timestamp is valid
            if entry["timestamp"]:
                log_data.append(entry)
    
    df = pd.DataFrame(log_data)
    if not df.empty and "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
        df = df[df["timestamp"].notna()]
    
    # Clean up actor column to ensure string type
    if 'actor' in df.columns:
        df['actor'] = df['actor'].astype(str)
    
    return df

# ================== ANALYSIS FUNCTIONS ==================

def analyze_xr_logs(logs: List[XRLogEntry]) -> Dict:
    df = pd.DataFrame([log.__dict__ for log in logs])
    analysis = {}
    
    # Basic stats
    analysis['total_events'] = len(df)
    analysis['time_range'] = f"{df['timestamp'].min()} to {df['timestamp'].max()}"
    
    # User and IP stats
    if 'target_type' in df.columns:
        analysis['unique_users'] = df[df['target_type'] == 'usr']['target'].nunique() if 'usr' in df['target_type'].values else 0
        analysis['unique_ips'] = df[df['target_type'] == 'IP']['target'].nunique() if 'IP' in df['target_type'].values else 0
    else:
        analysis['unique_users'] = 0
        analysis['unique_ips'] = 0
    
    # Event distribution
    if 'event_type' in df.columns:
        analysis['event_types'] = df['event_type'].value_counts().to_dict()
    else:
        analysis['event_types'] = {}
    
    if 'action' in df.columns:
        analysis['actions'] = df['action'].value_counts().to_dict()
    else:
        analysis['actions'] = {}
    
    # Top users and IPs
    if 'target_type' in df.columns:
        if 'usr' in df['target_type'].values:
            analysis['top_users'] = df[df['target_type'] == 'usr']['target'].value_counts().head(5).to_dict()
        else:
            analysis['top_users'] = {}
            
        if 'IP' in df['target_type'].values:
            analysis['top_ips'] = df[df['target_type'] == 'IP']['target'].value_counts().head(5).to_dict()
        else:
            analysis['top_ips'] = {}
    else:
        analysis['top_users'] = {}
        analysis['top_ips'] = {}
    
    # File operations
    if 'file_path' in df.columns:
        analysis['file_operations'] = df['file_path'].value_counts().head(5).to_dict()
    else:
        analysis['file_operations'] = {}
    
    # Security findings
    if 'file_path' in df.columns and 'event_type' in df.columns:
        sensitive_ops = df[(df['file_path'].isin(SENSITIVE_FILES)) & 
                          (df['event_type'].isin(['XR-FILE', 'XR-DEL', 'XR-EXEC']))]
        analysis['sensitive_operations'] = len(sensitive_ops)
    else:
        analysis['sensitive_operations'] = 0
    
    if 'event_type' in df.columns:
        analysis['process_kills'] = len(df[df['event_type'] == 'XR-SHDW'])
    else:
        analysis['process_kills'] = 0
    
    return analysis, df

def detect_anomalies(df):
    """Detect anomalies in logs using multiple rule sets."""
    anomalies = []

    # Rule 1: Shadow Copy + Process Kill
    shadow_queue = deque(maxlen=10)
    for _, row in df.iterrows():
        line = row['raw'].lower() if 'raw' in row else str(row).lower()
        if any(re.search(pattern, line) for pattern in SUSPICIOUS_RULES["Shadow Copy + Process Kill"]):
            shadow_queue.append(row)
            if len(shadow_queue) >= 2 and any(
                re.search(SUSPICIOUS_RULES["Shadow Copy + Process Kill"][1], r.raw.lower() if 'raw' in r else str(r).lower())
                for r in shadow_queue
            ):
                anomalies.append({
                    "timestamp": row['timestamp'] if 'timestamp' in row else None,
                    "actor": str(row['actor']) if 'actor' in row else None,
                    "action": str(row['action']) if 'action' in row else None,
                    "target": str(row['target']) if 'target' in row else None,
                    "rule": "Shadow Copy + Process Kill",
                    "reason": "Detected vssadmin shadow copy followed by process kill",
                    "raw": row['raw'] if 'raw' in row else str(row)
                })

    # Rule 2: User Escalation
    for _, row in df.iterrows():
        line = row['raw'].lower() if 'raw' in row else str(row).lower()
        if any(re.search(pattern, line) for pattern in SUSPICIOUS_RULES["User Escalation"]):
            anomalies.append({
                "timestamp": row['timestamp'] if 'timestamp' in row else None,
                "actor": str(row['actor']) if 'actor' in row else None,
                "action": str(row['action']) if 'action' in row else None,
                "target": str(row['target']) if 'target' in row else None,
                "rule": "User Escalation",
                "reason": "User attempted privilege escalation",
                "raw": row['raw'] if 'raw' in row else str(row)
            })

    # Rule 3: Unexpected File Deletion
    for _, row in df.iterrows():
        line = row['raw'].lower() if 'raw' in row else str(row).lower()
        if any(re.search(pattern, line) for pattern in SUSPICIOUS_RULES["Unexpected File Deletion"]):
            anomalies.append({
                "timestamp": row['timestamp'] if 'timestamp' in row else None,
                "actor": str(row['actor']) if 'actor' in row else None,
                "action": str(row['action']) if 'action' in row else None,
                "target": str(row['target']) if 'target' in row else None,
                "rule": "Unexpected File Deletion",
                "reason": "Suspicious file deletion detected",
                "raw": row['raw'] if 'raw' in row else str(row)
            })

    # Rule 4: Unusual Port Usage
    for _, row in df.iterrows():
        line = row['raw'].lower() if 'raw' in row else str(row).lower()
        if re.search(SUSPICIOUS_RULES["Unusual Port Usage"][0], line):
            anomalies.append({
                "timestamp": row['timestamp'] if 'timestamp' in row else None,
                "actor": str(row['actor']) if 'actor' in row else None,
                "action": str(row['action']) if 'action' in row else None,
                "target": str(row['target']) if 'target' in row else None,
                "rule": "Unusual Port Usage",
                "reason": "Outbound connection on high port (>49152)",
                "raw": row['raw'] if 'raw' in row else str(row)
            })

    # Rule 5: Persistence Behavior
    for _, row in df.iterrows():
        line = row['raw'].lower() if 'raw' in row else str(row).lower()
        if re.search(SUSPICIOUS_RULES["Persistence Behavior"][0], line):
            anomalies.append({
                "timestamp": row['timestamp'] if 'timestamp' in row else None,
                "actor": str(row['actor']) if 'actor' in row else None,
                "action": str(row['action']) if 'action' in row else None,
                "target": str(row['target']) if 'target' in row else None,
                "rule": "Persistence Behavior",
                "reason": "Registry modification for persistence detected",
                "raw": row['raw'] if 'raw' in row else str(row)
            })

    # Rule 6: Security Tools Disabled
    for _, row in df.iterrows():
        line = row['raw'].lower() if 'raw' in row else str(row).lower()
        if re.search(SUSPICIOUS_RULES["Security Tools Disabled"][0], line):
            anomalies.append({
                "timestamp": row['timestamp'] if 'timestamp' in row else None,
                "actor": str(row['actor']) if 'actor' in row else None,
                "action": str(row['action']) if 'action' in row else None,
                "target": str(row['target']) if 'target' in row else None,
                "rule": "Security Tools Disabled",
                "reason": "Attempt to disable security tools detected",
                "raw": row['raw'] if 'raw' in row else str(row)
            })

    # Rule 7: Exfiltration Suspicion
    for _, row in df.iterrows():
        line = row['raw'].lower() if 'raw' in row else str(row).lower()
        if any(re.search(pattern, line) for pattern in SUSPICIOUS_RULES["Exfiltration Suspicion"]):
            anomalies.append({
                "timestamp": row['timestamp'] if 'timestamp' in row else None,
                "actor": str(row['actor']) if 'actor' in row else None,
                "action": str(row['action']) if 'action' in row else None,
                "target": str(row['target']) if 'target' in row else None,
                "rule": "Exfiltration Suspicion",
                "reason": "Possible data exfiltration attempt detected",
                "raw": row['raw'] if 'raw' in row else str(row)
            })

    # Rule 8: Unusual Login Time (12am–6am)
    for _, row in df.iterrows():
        if 'timestamp' in row and row['timestamp'] and 0 <= row['timestamp'].hour < 6:
            anomalies.append({
                "timestamp": row['timestamp'],
                "actor": str(row['actor']) if 'actor' in row else None,
                "action": str(row['action']) if 'action' in row else None,
                "target": str(row['target']) if 'target' in row else None,
                "rule": "Unusual Login Time",
                "reason": f"Login at {row['timestamp'].strftime('%H:%M')}",
                "raw": row['raw'] if 'raw' in row else str(row)
            })

    # Rule 9: Multiple Failed Logins
    failed_attempts = {}
    for _, row in df.iterrows():
        line = row['raw'].lower() if 'raw' in row else str(row).lower()
        if "login failed" in line:
            key = str(row['actor']) if 'actor' in row else "unknown"
            failed_attempts[key] = failed_attempts.get(key, 0) + 1
            if failed_attempts[key] >= 5:
                anomalies.append({
                    "timestamp": row['timestamp'] if 'timestamp' in row else None,
                    "actor": str(row['actor']) if 'actor' in row else None,
                    "action": str(row['action']) if 'action' in row else None,
                    "target": str(row['target']) if 'target' in row else None,
                    "rule": "Multiple Failed Logins",
                    "reason": f"{failed_attempts[key]} consecutive login failures",
                    "raw": row['raw'] if 'raw' in row else str(row)
                })

    return pd.DataFrame(anomalies)

def generate_summary(df):
    """Generate summary statistics."""
    if df.empty or "timestamp" not in df.columns:
        return {"error": "No valid logs to summarize"}
    earliest = df['timestamp'].min().isoformat() if not df['timestamp'].isnull().all() else "N/A"
    latest = df['timestamp'].max().isoformat() if not df['timestamp'].isnull().all() else "N/A"
    actors = df['actor'].nunique() if 'actor' in df.columns else 0
    entries = len(df)
    
    # Add XR-specific stats if available
    xr_stats = {}
    if 'event_type' in df.columns and df['event_type'].str.startswith('XR-').any():
        xr_stats = {
            "unique_users": df[df['target_type'] == 'usr']['target'].nunique() if 'target_type' in df.columns and 'target' in df.columns else 0,
            "unique_ips": df[df['target_type'] == 'IP']['target'].nunique() if 'target_type' in df.columns and 'target' in df.columns else 0,
            "sensitive_operations": len(df[(df['file_path'].isin(SENSITIVE_FILES)) & 
                                    (df['event_type'].isin(['XR-FILE', 'XR-DEL', 'XR-EXEC']))]) if 'file_path' in df.columns and 'event_type' in df.columns else 0,
            "process_kills": len(df[df['event_type'] == 'XR-SHDW']) if 'event_type' in df.columns else 0
        }
    
    return {
        "total_entries": entries,
        "unique_actors": actors,
        "time_range": {"start": earliest, "end": latest},
        "xr_specific_stats": xr_stats
    }

# ================== VISUALIZATION FUNCTIONS ==================

def generate_event_type_chart(df: pd.DataFrame) -> Optional[bytes]:
    if 'event_type' not in df.columns or df['event_type'].empty:
        return None
    
    fig, ax = plt.subplots(figsize=(10, 6))
    df['event_type'].value_counts().plot(kind='bar', ax=ax, color='skyblue')
    ax.set_title('Event Type Distribution')
    ax.set_xlabel('Event Type')
    ax.set_ylabel('Count')
    plt.tight_layout()
    
    buf = BytesIO()
    plt.savefig(buf, format='png', dpi=150)
    plt.close()
    buf.seek(0)
    return buf

def generate_top_users_chart(df: pd.DataFrame) -> Optional[bytes]:
    if 'actor' not in df.columns or df['actor'].empty:
        return None
    
    top_users = df['actor'].value_counts().head(5)
    if top_users.empty:
        return None
    
    fig, ax = plt.subplots(figsize=(10, 6))
    top_users.plot(kind='bar', ax=ax, color='lightgreen')
    ax.set_title('Top Users by Activity')
    ax.set_xlabel('User')
    ax.set_ylabel('Count')
    plt.tight_layout()
    
    buf = BytesIO()
    plt.savefig(buf, format='png', dpi=150)
    plt.close()
    buf.seek(0)
    return buf

def generate_top_ips_chart(df: pd.DataFrame) -> Optional[bytes]:
    if 'target_type' not in df.columns or 'IP' not in df['target_type'].values:
        return None
    
    top_ips = df[df['target_type'] == 'IP']['target'].value_counts().head(5)
    if top_ips.empty:
        return None
    
    fig, ax = plt.subplots(figsize=(10, 6))
    top_ips.plot(kind='bar', ax=ax, color='salmon')
    ax.set_title('Top IPs by Connections')
    ax.set_xlabel('IP Address')
    ax.set_ylabel('Count')
    plt.tight_layout()
    
    buf = BytesIO()
    plt.savefig(buf, format='png', dpi=150)
    plt.close()
    buf.seek(0)
    return buf

def generate_visuals(df, anomalies, output_dir):
    """Generate graphs using matplotlib and plotly."""
    if df.empty or "timestamp" not in df.columns:
        print(Fore.YELLOW + "[!] No data to visualize.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.set_index("timestamp", inplace=True)
    resampled = df.resample("H").size()

    # Event frequency over time
    try:
        plt.figure(figsize=(10, 5))
        if not resampled.empty:
            resampled.plot(title="Event Frequency Over Time")
        else:
            plt.text(0.5, 0.5, "No Data", ha='center')
        plt.savefig(os.path.join(output_dir, "event_frequency.png"))
        plt.close()
    except Exception as e:
        print(Fore.RED + f"[!] Failed to generate event_frequency plot: {e}")

    try:
        fig = px.line(resampled.reset_index(), x="timestamp", y=0, title="Event Frequency Over Time")
        fig.write_html(os.path.join(output_dir, "event_frequency.html"))
    except Exception as e:
        print(Fore.RED + f"[!] Failed to generate event_frequency HTML: {e}")

    # User activity
    if 'actor' in df.columns:
        user_counts = df.groupby("actor").size().sort_values(ascending=False).head(10)
        try:
            plt.figure(figsize=(10, 5))
            if not user_counts.empty:
                user_counts.plot(kind="bar", title="Top Users by Activity")
            else:
                plt.text(0.5, 0.5, "No Data", ha='center')
            plt.savefig(os.path.join(output_dir, "user_activity.png"))
            plt.close()
        except Exception as e:
            print(Fore.RED + f"[!] Failed to generate user_activity plot: {e}")

        try:
            fig = px.bar(user_counts.reset_index(), x="actor", y=0, title="Top Users by Activity")
            fig.write_html(os.path.join(output_dir, "user_activity.html"))
        except Exception as e:
            print(Fore.RED + f"[!] Failed to generate user_activity HTML: {e}")

    # Anomaly timeline
    if not anomalies.empty:
        anomalies["timestamp"] = pd.to_datetime(anomalies["timestamp"])
        try:
            plt.figure(figsize=(10, 3))
            plt.scatter(anomalies["timestamp"], [1]*len(anomalies), c='red')
            plt.yticks([])
            plt.title("Anomaly Timeline")
            plt.savefig(os.path.join(output_dir, "anomalies.png"))
            plt.close()
        except Exception as e:
            print(Fore.RED + f"[!] Failed to generate anomalies plot: {e}")

        try:
            fig = px.scatter(anomalies, x="timestamp", y=[1]*len(anomalies), 
                            hover_data=["action", "rule", "target"], title="Anomaly Timeline")
            fig.write_html(os.path.join(output_dir, "anomalies.html"))
        except Exception as e:
            print(Fore.RED + f"[!] Failed to generate anomalies HTML: {e}")

# ================== REPORT GENERATION ==================

class PDFReport(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 16)
        self.cell(0, 10, 'Log Analysis Report', align='C', ln=True)
        self.ln(10)
    
    def add_image(self, img_bytes, title):
        if img_bytes is None:
            self.set_font('helvetica', 'I', 10)
            self.cell(0, 5, f"{title} - No data available", ln=True)
            return
            
        temp_img = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
        temp_img.write(img_bytes.read())
        temp_img.close()
        
        self.set_font('helvetica', 'B', 12)
        self.cell(0, 10, title, ln=True)
        self.image(temp_img.name, x=10, w=190)
        self.ln(5)
    
    def add_section(self, title, content):
        self.set_font('helvetica', 'B', 12)
        self.cell(0, 10, title, ln=True)
        self.set_font('helvetica', '', 10)
        if isinstance(content, dict):
            if not content:
                self.cell(0, 5, "No data available", ln=True)
            else:
                for k, v in content.items():
                    self.cell(0, 5, f"{k}: {v}", ln=True)
        else:
            self.multi_cell(0, 5, str(content))
        self.ln(5)

def generate_pdf_report(analysis: Dict, df: pd.DataFrame, anomalies: pd.DataFrame) -> bytes:
    pdf = PDFReport()
    pdf.add_page()
    
    # Generate charts
    event_chart = generate_event_type_chart(df)
    users_chart = generate_top_users_chart(df)
    ips_chart = generate_top_ips_chart(df)
    
    # Summary section
    summary = generate_summary(df)
    pdf.add_section("Summary", {
        "Total Events": summary['total_entries'],
        "Time Range": f"{summary['time_range']['start']} to {summary['time_range']['end']}",
        "Unique Users": summary['unique_actors'],
        "Unique IPs": summary.get('xr_specific_stats', {}).get('unique_ips', 'N/A'),
        "Sensitive Operations": summary.get('xr_specific_stats', {}).get('sensitive_operations', 'N/A'),
        "Process Kills": summary.get('xr_specific_stats', {}).get('process_kills', 'N/A')
    })
    
    # Charts section
    pdf.add_image(event_chart, "Event Type Distribution")
    pdf.add_image(users_chart, "Top Users by Activity")
    pdf.add_image(ips_chart, "Top IPs by Connections")
    
    # Event analysis
    if 'event_type' in df.columns:
        pdf.add_section("Event Types", df['event_type'].value_counts().to_dict())
    if 'action' in df.columns:
        pdf.add_section("Actions", df['action'].value_counts().to_dict())
    
    # Top entities
    if 'target_type' in df.columns:
        if 'usr' in df['target_type'].values:
            pdf.add_section("Top Users", df[df['target_type'] == 'usr']['target'].value_counts().head(5).to_dict())
        if 'IP' in df['target_type'].values:
            pdf.add_section("Top IPs", df[df['target_type'] == 'IP']['target'].value_counts().head(5).to_dict())
    
    # Security findings
    if not anomalies.empty:
        pdf.add_section("Security Findings", {
            "Total Anomalies": len(anomalies),
            "Anomaly Types": anomalies['rule'].value_counts().to_dict()
        })
    
    return pdf.output()

def generate_html_report(analysis: Dict, df: pd.DataFrame, anomalies: pd.DataFrame) -> str:
    # Generate charts and convert to base64
    def get_chart_base64(chart_func):
        buf = chart_func(df)
        if buf is None:
            return None
        return base64.b64encode(buf.getvalue()).decode('utf-8')
    
    event_chart = get_chart_base64(generate_event_type_chart)
    users_chart = get_chart_base64(generate_top_users_chart)
    ips_chart = get_chart_base64(generate_top_ips_chart)
    
    summary = generate_summary(df)
    
    html_content = f"""
    <html>
    <head>
        <title>Log Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #444; margin-top: 20px; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .section {{ margin-bottom: 30px; }}
            .chart {{ margin: 20px 0; text-align: center; }}
            img {{ max-width: 100%; height: auto; }}
            .no-data {{ color: #999; font-style: italic; }}
            .anomaly {{ background-color: #ffdddd; }}
        </style>
    </head>
    <body>
        <h1>Log Analysis Report</h1>
        
        <div class="section">
            <h2>Summary</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Total Events</td><td>{summary['total_entries']}</td></tr>
                <tr><td>Time Range</td><td>{summary['time_range']['start']} to {summary['time_range']['end']}</td></tr>
                <tr><td>Unique Users</td><td>{summary['unique_actors']}</td></tr>
                <tr><td>Unique IPs</td><td>{summary.get('xr_specific_stats', {}).get('unique_ips', 'N/A')}</td></tr>
                <tr><td>Sensitive Operations</td><td>{summary.get('xr_specific_stats', {}).get('sensitive_operations', 'N/A')}</td></tr>
                <tr><td>Process Kills</td><td>{summary.get('xr_specific_stats', {}).get('process_kills', 'N/A')}</td></tr>
            </table>
        </div>
    """
    
    # Event type chart
    html_content += """
    <div class="section">
        <h2>Event Type Distribution</h2>
        <div class="chart">
    """
    if event_chart:
        html_content += f'<img src="data:image/png;base64,{event_chart}" alt="Event Type Chart">'
    else:
        html_content += '<p class="no-data">No event type data available</p>'
    html_content += "</div></div>"
    
    # Top users
    html_content += """
    <div class="section">
        <h2>Top Users by Activity</h2>
        <div class="chart">
    """
    if users_chart:
        html_content += f'<img src="data:image/png;base64,{users_chart}" alt="Top Users Chart">'
    else:
        html_content += '<p class="no-data">No user data available</p>'
    
    if 'actor' in df.columns:
        top_users = df['actor'].value_counts().head(5).to_dict()
        if top_users:
            html_content += """
                <table>
                    <tr><th>User</th><th>Count</th></tr>
            """
            for user, count in top_users.items():
                html_content += f"<tr><td>{user}</td><td>{count}</td></tr>"
            html_content += "</table>"
    html_content += "</div></div>"
    
    # Top IPs
    html_content += """
    <div class="section">
        <h2>Top IPs by Connections</h2>
        <div class="chart">
    """
    if ips_chart:
        html_content += f'<img src="data:image/png;base64,{ips_chart}" alt="Top IPs Chart">'
    else:
        html_content += '<p class="no-data">No IP data available</p>'
    
    if 'target_type' in df.columns and 'IP' in df['target_type'].values:
        top_ips = df[df['target_type'] == 'IP']['target'].value_counts().head(5).to_dict()
        if top_ips:
            html_content += """
                <table>
                    <tr><th>IP Address</th><th>Count</th></tr>
            """
            for ip, count in top_ips.items():
                html_content += f"<tr><td>{ip}</td><td>{count}</td></tr>"
            html_content += "</table>"
    html_content += "</div></div>"
    
    # Security findings
    html_content += f"""
    <div class="section">
        <h2>Security Findings</h2>
    """
    if not anomalies.empty:
        html_content += f"""
        <p>Total anomalies detected: {len(anomalies)}</p>
        <table>
            <tr><th>Timestamp</th><th>Rule</th><th>Actor</th><th>Action</th><th>Reason</th></tr>
        """
        for _, row in anomalies.iterrows():
            html_content += f"""
            <tr class="anomaly">
                <td>{row['timestamp']}</td>
                <td>{row['rule']}</td>
                <td>{row['actor'] if pd.notna(row['actor']) else 'N/A'}</td>
                <td>{row['action'] if pd.notna(row['action']) else 'N/A'}</td>
                <td>{row['reason']}</td>
            </tr>
            """
        html_content += "</table>"
    else:
        html_content += "<p>No security anomalies detected.</p>"
    html_content += "</div>"
    
    # Sample logs
    html_content += f"""
    <div class="section">
        <h2>Sample Logs</h2>
        {df.head(10).to_html(index=False)}
    </div>
    </body>
    </html>
    """
    
    return html_content

# ================== STREAMLIT UI ==================

def run_streamlit_ui():
    st.set_page_config(page_title="Log Analyzer", layout="wide")
    st.title("🔍 Comprehensive Log Analysis Dashboard")
    
    # File upload
    uploaded_files = st.file_uploader("Upload log files", type=["txt", "log", "csv"], accept_multiple_files=True)
    
    if not uploaded_files:
        st.info("Please upload log files to begin analysis")
        return
    
    # Parse logs
    with st.spinner("Parsing logs..."):
        df = parse_logs(uploaded_files)
    
    if df.empty:
        st.error("No valid log entries found in the files")
        return
    
    # Perform analysis
    with st.spinner("Analyzing logs..."):
        analysis = generate_summary(df)
        anomalies = detect_anomalies(df)
    
    # Display results
    st.header("📊 Analysis Summary")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", analysis['total_entries'])
    col2.metric("Unique Users", analysis['unique_actors'])
    col3.metric("Time Range", f"{analysis['time_range']['start'].split('T')[0]} to {analysis['time_range']['end'].split('T')[0]}")
    col4.metric("Anomalies", len(anomalies))
    
    # Filters
    st.sidebar.header("Filters")
    if 'actor' in df.columns:
        users = sorted(df['actor'].unique())
        selected_users = st.sidebar.multiselect("Filter by user", options=users, default=users)
        df = df[df['actor'].isin(selected_users)]
    
    min_time, max_time = df['timestamp'].min(), df['timestamp'].max()
    time_range = st.sidebar.slider(
        "Time Range",
        min_value=min_time.to_pydatetime(),
        max_value=max_time.to_pydatetime(),
        value=(min_time.to_pydatetime(), max_time.to_pydatetime())
    )
    df = df[df['timestamp'].between(*pd.to_datetime(time_range))]
    
    # Tabs for different views
    tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Event Analysis", "Anomalies", "Raw Data"])
    
    with tab1:
        st.subheader("Event Timeline")
        
        # Event frequency over time
        freq = 'H' if (df['timestamp'].max() - df['timestamp'].min()).days < 7 else 'D'
        freq_label = "Hour" if freq == 'H' else "Day"
        resampled = df.resample(freq, on='timestamp').size().reset_index(name='count')
        
        fig = px.line(resampled, x='timestamp', y='count', title=f"Event Frequency per {freq_label}")
        st.plotly_chart(fig)
        
        # User activity
        if 'actor' in df.columns:
            user_counts = df.groupby('actor').size().sort_values(ascending=False).head(10)
            fig = px.bar(user_counts.reset_index(), x='actor', y=0, title="Top Users by Activity")
            st.plotly_chart(fig)
    
    with tab2:
        st.subheader("Event Type Analysis")
        
        if 'event_type' in df.columns:
            # Event type distribution
            event_chart = generate_event_type_chart(df)
            if event_chart:
                st.image(event_chart)
            else:
                st.warning("No event type data available")
            
            # Event type details
            st.dataframe(df['event_type'].value_counts().reset_index().rename(columns={'index': 'Event Type', 'event_type': 'Count'}))
        else:
            st.warning("No event type information in logs")
    
    with tab3:
        st.subheader("Detected Anomalies")
        
        if not anomalies.empty:
            # Filter anomalies
            filter_rule = st.selectbox("Filter by rule", ["All"] + list(anomalies['rule'].unique()))
            keyword = st.text_input("Search anomalies")
            
            filtered = anomalies.copy()
            if filter_rule != "All":
                filtered = filtered[filtered['rule'] == filter_rule]
            if keyword:
                filtered = filtered[filtered['raw'].str.contains(keyword, case=False)]
            
            # Display filtered anomalies
            st.dataframe(filtered[['timestamp', 'rule', 'actor', 'action', 'reason']])
            
            # Anomaly statistics
            st.subheader("Anomaly Statistics")
            rule_counts = Counter(filtered['rule'])
            st.bar_chart(pd.Series(rule_counts))
        else:
            st.success("No anomalies detected")
    
    with tab4:
        st.subheader("Raw Log Data")
        st.dataframe(df)
    
    # Generate reports
    st.sidebar.header("Report Generation")
    report_format = st.sidebar.selectbox("Report Format", ["PDF", "HTML", "JSON"])
    
    if st.sidebar.button("Generate Report"):
        with st.spinner(f"Generating {report_format} report..."):
            if report_format == "PDF":
                pdf_bytes = generate_pdf_report(analysis, df, anomalies)
                st.download_button(
                    "Download PDF Report",
                    data=BytesIO(pdf_bytes).read(),
                    file_name="log_analysis.pdf",
                    mime="application/pdf"
                )
            elif report_format == "HTML":
                html_report = generate_html_report(analysis, df, anomalies)
                st.download_button(
                    "Download HTML Report",
                    data=html_report,
                    file_name="log_analysis.html",
                    mime="text/html"
                )
            elif report_format == "JSON":
                json_report = json.dumps({
                    "summary": analysis,
                    "sample_logs": json.loads(df.head(10).to_json(orient='records')),
                    "anomalies": json.loads(anomalies.to_json(orient='records'))
                }, indent=2)
                st.download_button(
                    "Download JSON Report",
                    data=json_report,
                    file_name="log_analysis.json",
                    mime="application/json"
                )

# ================== CLI INTERFACE ==================

def cli_main():
    parser = argparse.ArgumentParser(description="Comprehensive Log Analysis Tool")
    parser.add_argument("logdir", help="Directory containing log files")
    parser.add_argument("--summary", action="store_true", help="Generate summary report")
    parser.add_argument("--timeline", action="store_true", help="Generate sorted timeline")
    parser.add_argument("--alerts", action="store_true", help="Detect anomalies")
    parser.add_argument("--visuals", action="store_true", help="Generate visualizations")
    parser.add_argument("--output", default="log_analysis_output", help="Output directory")
    args = parser.parse_args()

    print(Fore.CYAN + "[+] Parsing logs...")
    df = parse_logs(args.logdir)

    os.makedirs(args.output, exist_ok=True)

    summary = {}
    timeline = df
    anomalies = pd.DataFrame()

    if args.summary:
        print(Fore.CYAN + "[+] Generating summary...")
        summary = generate_summary(df)
        with open(os.path.join(args.output, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2)

    if args.timeline:
        print(Fore.CYAN + "[+] Sorting timeline...")
        timeline = df.sort_values("timestamp")
        timeline.to_csv(os.path.join(args.output, "timeline.csv"), index=False)

    if args.alerts:
        print(Fore.CYAN + "[+] Detecting anomalies...")
        anomalies = detect_anomalies(timeline)
        if not anomalies.empty:
            anomalies.to_csv(os.path.join(args.output, "anomalies.csv"), index=False)
            print(Fore.YELLOW + f"[!] Found {len(anomalies)} anomalies")
        else:
            print(Fore.GREEN + "[+] No anomalies detected")

    if args.visuals:
        print(Fore.CYAN + "[+] Generating visualizations...")
        generate_visuals(timeline, anomalies, args.output)

    print(Fore.GREEN + f"[+] Analysis complete. Results saved to '{args.output}'")

# ================== MAIN ENTRY POINT ==================

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != 'streamlit':
        cli_main()
    else:
        if IS_STREAMLIT:
            # Fix potential PyFPDF/fpdf2 conflict
            try:
                subprocess.run(["pip", "uninstall", "--yes", "pypdf"], check=True)
                subprocess.run(["pip", "install", "--upgrade", "fpdf2"], check=True)
            except:
                pass
            
            run_streamlit_ui()
        else:
            print("Streamlit is not available. Running in CLI mode.")
            cli_main()