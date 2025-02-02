import asyncio
import aiohttp
import dns.resolver
import json
import logging
import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from typing import Set, Dict, List, Optional
import tldextract
from datetime import datetime
from pathlib import Path
import subprocess
import requests
import whois
import shodan
import censys.ipv4
import censys.certificates
import ssl
import OpenSSL
import aiodns
import concurrent.futures
import sys
import os
import re
import time
import random
import urllib3
import yaml
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style

class AdvancedSubdomainScanner:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Advanced Subdomain Scanner Pro 2.0")
        self.root.geometry("1200x800")
        self.setup_theme()
        
        # Initialize variables
        self.is_running = False
        self.current_tasks = []
        self.discovered_subdomains = set()
        self.api_keys = {}
        
        # Setup components
        self.setup_logging()
        self.load_config()
        self.load_api_keys()
        self.create_gui()

    def setup_theme(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="white")
        style.configure("TButton", padding=5)
        style.configure("Accent.TButton", background="#007acc")
        
    def setup_logging(self):
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            filename=log_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def load_config(self):
        try:
            with open('config.yaml', 'r') as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            self.config = {
                'scanning': {
                    'timeout': 30,
                    'max_threads': 50,
                    'max_retries': 3,
                    'delay': 0.1
                },
                'dns_servers': [
                    '8.8.8.8', '8.8.4.4',  # Google
                    '1.1.1.1', '1.0.0.1',  # Cloudflare
                    '9.9.9.9',             # Quad9
                    '208.67.222.222'       # OpenDNS
                ],
                'ports': {
                    'common': [80, 443, 8080, 8443],
                    'extended': [21, 22, 25, 53, 110, 123, 143, 445, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 6379],
                    'full': range(1, 1025)
                },
                'wordlists': {
                    'small': 'wordlists/small.txt',
                    'medium': 'wordlists/medium.txt',
                    'large': 'wordlists/large.txt',
                    'custom': 'wordlists/custom.txt'
                }
            }
            self.save_config()

    def save_config(self):
        with open('config.yaml', 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)

    def load_api_keys(self):
        try:
            with open('api_keys.yaml', 'r') as f:
                self.api_keys = yaml.safe_load(f)
        except FileNotFoundError:
            self.api_keys = {
                'shodan': '',
                'censys_id': '',
                'censys_secret': '',
                'virustotal': '',
                'securitytrails': '',
                'binaryedge': '',
                'spyse': '',
                'threatcrowd': '',
                'urlscan': ''
            }
            self.save_api_keys()

    def save_api_keys(self):
        with open('api_keys.yaml', 'w') as f:
            yaml.dump(self.api_keys, f, default_flow_style=False)

    def create_gui(self):
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Create notebook for different sections
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create tabs
        self.create_scanner_tab()
        self.create_tools_tab()
        self.create_settings_tab()
        self.create_results_tab()
        self.create_status_bar()

    def create_scanner_tab(self):
        scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(scanner_frame, text="Scanner")

        # Input area
        input_frame = ttk.LabelFrame(scanner_frame, text="Target Input", padding=5)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        # Domain entry
        ttk.Label(input_frame, text="Domain:").pack(side=tk.LEFT, padx=5)
        self.domain_var = tk.StringVar()
        self.domain_entry = ttk.Entry(input_frame, textvariable=self.domain_var, width=40)
        self.domain_entry.pack(side=tk.LEFT, padx=5)

        # Buttons
        self.start_button = ttk.Button(
            input_frame,
            text="Start Scan",
            command=self.start_scan,
            style="Accent.TButton"
        )
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(
            input_frame,
            text="Stop",
            command=self.stop_scan,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Options area
        options_frame = ttk.LabelFrame(scanner_frame, text="Scan Options", padding=5)
        options_frame.pack(fill=tk.BOTH, padx=5, pady=5)

        # Create scanning options
        self.create_scanning_options(options_frame)

    def create_scanning_options(self, parent):
        # Create frames for different option categories
        basic_frame = ttk.LabelFrame(parent, text="Basic Techniques", padding=5)
        basic_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        advanced_frame = ttk.LabelFrame(parent, text="Advanced Techniques", padding=5)
        advanced_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

        passive_frame = ttk.LabelFrame(parent, text="Passive Techniques", padding=5)
        passive_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        active_frame = ttk.LabelFrame(parent, text="Active Techniques", padding=5)
        active_frame.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

        # Configure grid weights
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)

        # Basic techniques
        self.basic_options = {
            "dns_a": "DNS A Records",
            "dns_aaaa": "DNS AAAA Records",
            "dns_cname": "DNS CNAME",
            "dns_mx": "DNS MX",
            "dns_ns": "DNS NS",
            "dns_txt": "DNS TXT",
            "dns_srv": "DNS SRV"
        }

        # Advanced techniques
        self.advanced_options = {
            "zone_transfer": "Zone Transfer",
            "wildcard_detection": "Wildcard Detection",
            "tld_enumeration": "TLD Enumeration",
            "recursive_search": "Recursive Search",
            "permutation_scan": "Permutation Scan",
            "alteration_scan": "Alteration Scan"
        }

        # Passive techniques
        self.passive_options = {
            "certificate_search": "Certificate Search",
            "wayback_machine": "Wayback Machine",
            "virustotal": "VirusTotal",
            "securitytrails": "SecurityTrails",
            "threatcrowd": "ThreatCrowd",
            "crtsh": "crt.sh",
            "censys": "Censys",
            "shodan": "Shodan",
            "urlscan": "URLScan",
            "dnsdumpster": "DNSDumpster"
        }

        # Active techniques
        self.active_options = {
            "port_scan": "Port Scan",
            "service_detection": "Service Detection",
            "screenshot": "Take Screenshots",
            "http_probe": "HTTP Probe",
            "vulnerability_scan": "Vulnerability Scan",
            "brute_force": "Brute Force"
        }

        # Create checkboxes
        self.create_option_checkboxes(basic_frame, self.basic_options, "basic")
        self.create_option_checkboxes(advanced_frame, self.advanced_options, "advanced")
        self.create_option_checkboxes(passive_frame, self.passive_options, "passive")
        self.create_option_checkboxes(active_frame, self.active_options, "active")

    def create_option_checkboxes(self, parent, options, prefix):
        self.scan_options = {}
        for i, (key, text) in enumerate(options.items()):
            var = tk.BooleanVar(value=True)
            self.scan_options[f"{prefix}_{key}"] = var
            ttk.Checkbutton(
                parent,
                text=text,
                variable=var
            ).grid(row=i//2, column=i%2, padx=5, pady=2, sticky='w')

    def create_tools_tab(self):
        tools_frame = ttk.Frame(self.notebook)
        self.notebook.add(tools_frame, text="Tools")

        # Create tool categories
        categories = [
            ("Enumeration Tools", self.enumeration_tools),
            ("DNS Tools", self.dns_tools),
            ("Network Tools", self.network_tools),
            ("Web Tools", self.web_tools),
            ("Misc Tools", self.misc_tools)
        ]

        row = 0
        for title, tools in categories:
            frame = ttk.LabelFrame(tools_frame, text=title, padding=5)
            frame.grid(row=row, column=0, padx=5, pady=5, sticky="ew")
            
            for i, (name, command) in enumerate(tools.items()):
                ttk.Button(
                    frame,
                    text=name,
                    command=command
                ).grid(row=i//4, column=i%4, padx=5, pady=2, sticky="ew")
            
            row += 1

        tools_frame.grid_columnconfigure(0, weight=1)

    @property
    def enumeration_tools(self):
        return {
            "Sublist3r": self.run_sublister,
            "Amass": self.run_amass,
            "Subfinder": self.run_subfinder,
            "AssetFinder": self.run_assetfinder,
            "Findomain": self.run_findomain
        }

    @property
    def dns_tools(self):
        return {
            "MassDNS": self.run_massdns,
            "DNSRecon": self.run_dnsrecon,
            "Fierce": self.run_fierce,
            "DNSMap": self.run_dnsmap,
            "DNSEnum": self.run_dnsenum
        }

    @property
    def network_tools(self):
        return {
            "Nmap": self.run_nmap,
            "Masscan": self.run_masscan,
            "ZMap": self.run_zmap,
            "WafW00f": self.run_wafw00f,
            "SSLScan": self.run_sslscan
        }

    @property
    def web_tools(self):
        return {
            "Gobuster": self.run_gobuster,
            "Dirsearch": self.run_dirsearch,
            "Nikto": self.run_nikto,
            "WPScan": self.run_wpscan,
            "Whatweb": self.run_whatweb
        }

    @property
    def misc_tools(self):
        return {
            "TheHarvester": self.run_theharvester,
            "Photon": self.run_photon,
            "EyeWitness": self.run_eyewitness,
            "Aquatone": self.run_aquatone,
            "CloudFlair": self.run_cloudflair
        }

    # Tool execution methods
    def run_sublister(self):
        # Implementation for Sublist3r
        pass

    def run_amass(self):
        # Implementation for Amass
        pass

    # ... Add similar methods for all other tools ...

    def create_settings_tab(self):
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")

        # Create settings categories
        self.create_general_settings(settings_frame)
        self.create_api_settings(settings_frame)
        self.create_advanced_settings(settings_frame)

    def create_results_tab(self):
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")

        # Create results view
        self.create_results_view(results_frame)

    def create_status_bar(self):
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=2)

        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT, padx=5)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            status_frame,
            variable=self.progress_var,
            maximum=100,
            length=200
        )
        self.progress_bar.pack(side=tk.RIGHT, padx=5)

    # ... [Continue with Part 2] ...

