#!/usr/bin/env python3
import asyncio
import json
import dns.resolver
import dns.query
import dns.exception
import dns.flags
import logging
import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime
from pathlib import Path
import random
import tldextract

class AdvancedSubdomainScanner:
    def __init__(self, root: tk.Tk, config_path="config.json"):
        self.root = root
        self.root.title("Advanced Subdomain & Enumeration Scanner")
        self.root.geometry("1400x900")
        self.setup_theme()
        self.is_running = False
        self.discovered_subdomains = set()
        self.load_config(config_path)
        self.setup_logging()
        self.create_gui()

    def setup_theme(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="white")
        style.configure("TButton", padding=5)
        style.configure("Accent.TButton", background="#007acc")
        style.configure("TLabelframe", background="#2b2b2b", foreground="white")
        style.configure("TLabelframe.Label", background="#2b2b2b", foreground="white")

    def load_config(self, config_path):
        try:
            with open(config_path, "r") as f:
                self.config = json.load(f)
        except Exception as e:
            messagebox.showerror("Config Error", f"Error loading configuration: {e}")
            self.config = {}

    def setup_logging(self):
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        logging.basicConfig(
            filename=log_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

    def create_gui(self):
        # Main container with Notebook tabs
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.create_scanner_tab()
        self.create_results_tab()
        self.create_settings_tab()
        self.create_status_bar()

    def create_scanner_tab(self):
        scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(scanner_frame, text="Scanner")

        # Target input area
        input_frame = ttk.LabelFrame(scanner_frame, text="Target Input", padding=5)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(input_frame, text="Domain:").pack(side=tk.LEFT, padx=5)
        self.domain_var = tk.StringVar()
        self.domain_entry = ttk.Entry(input_frame, textvariable=self.domain_var, width=50)
        self.domain_entry.pack(side=tk.LEFT, padx=5)

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

        # Wordlist selection area
        wordlist_frame = ttk.LabelFrame(scanner_frame, text="Wordlist Selection", padding=5)
        wordlist_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(wordlist_frame, text="Wordlist Path:").pack(side=tk.LEFT, padx=5)
        # Default value from config (use "custom" if available, otherwise an empty string)
        default_wordlist = self.config.get("wordlists", {}).get("custom", "")
        self.wordlist_path = tk.StringVar(value=default_wordlist)
        self.wordlist_entry = ttk.Entry(wordlist_frame, textvariable=self.wordlist_path, width=50)
        self.wordlist_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(wordlist_frame, text="Browse", command=self.browse_wordlist).pack(side=tk.LEFT, padx=5)

        # Options panels for basic, advanced, and active techniques
        options_frame = ttk.LabelFrame(scanner_frame, text="Scan Options", padding=5)
        options_frame.pack(fill=tk.BOTH, padx=5, pady=5)

        # Create subframes for different levels
        basic_frame = ttk.LabelFrame(options_frame, text="Basic Techniques", padding=5)
        basic_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        advanced_frame = ttk.LabelFrame(options_frame, text="Advanced Techniques", padding=5)
        advanced_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        active_frame = ttk.LabelFrame(options_frame, text="Active Techniques", padding=5)
        active_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        options_frame.grid_columnconfigure(0, weight=1)
        options_frame.grid_columnconfigure(1, weight=1)

        # Define option groups (checkbox texts and keys)
        self.basic_options = {
            "dns_a": "DNS A Records Brute-force"
        }
        self.advanced_options = {
            "zone_transfer": "Zone Transfer",
            "wildcard_detection": "Wildcard Detection",
            "tld_enumeration": "TLD Enumeration",
            "recursive_search": "Recursive Search",
            "permutation_scan": "Permutation Scan",
            "alteration_scan": "Alteration Scan",
            "dnssec_check": "DNSSEC Check",
            "caa_enumeration": "CAA Record Enumeration",
            "takeover_detection": "Subdomain Takeover Detection"
        }
        self.active_options = {
            "port_scan": "Port Scan",
            "service_detection": "Service Detection",
            "http_probe": "HTTP Probe"
        }
        self.scan_options = {}
        self.create_option_checkboxes(basic_frame, self.basic_options, "basic")
        self.create_option_checkboxes(advanced_frame, self.advanced_options, "advanced")
        self.create_option_checkboxes(active_frame, self.active_options, "active")

    def browse_wordlist(self):
        file_path = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            self.wordlist_path.set(file_path)

    def create_option_checkboxes(self, parent, options, prefix):
        for i, (key, text) in enumerate(options.items()):
            var = tk.BooleanVar(value=True)
            self.scan_options[f"{prefix}_{key}"] = var
            ttk.Checkbutton(parent, text=text, variable=var)\
                .grid(row=i // 2, column=i % 2, padx=5, pady=2, sticky="w")

    def create_results_tab(self):
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(results_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_frame, text="Save Results", command=self.save_results).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT)

    def create_settings_tab(self):
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        settings_text = scrolledtext.ScrolledText(settings_frame, wrap=tk.WORD, font=("Consolas", 10), height=15)
        settings_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        settings_text.insert(tk.END, json.dumps(self.config, indent=4))
        settings_text.config(state=tk.DISABLED)

    def create_status_bar(self):
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=2)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100, length=250)
        self.progress_bar.pack(side=tk.RIGHT, padx=5)

    def start_scan(self):
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain to scan")
            return

        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)
        self.discovered_subdomains.clear()
        self.status_var.set("Scanning...")
        self.progress_var.set(0)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.run_scan(domain))
        finally:
            loop.close()

    async def run_scan(self, domain):
        tasks = []
        total_tasks = 0

        # Basic Techniques
        if self.scan_options.get("basic_dns_a").get():
            tasks.append(self.dns_bruteforce(domain))
            total_tasks += 1

        # Advanced Techniques
        if self.scan_options.get("advanced_zone_transfer").get():
            tasks.append(self.zone_transfer(domain))
            total_tasks += 1
        if self.scan_options.get("advanced_wildcard_detection").get():
            tasks.append(self.wildcard_detection(domain))
            total_tasks += 1
        if self.scan_options.get("advanced_tld_enumeration").get():
            tasks.append(self.tld_enumeration(domain))
            total_tasks += 1
        if self.scan_options.get("advanced_recursive_search").get():
            tasks.append(self.recursive_search(domain))
            total_tasks += 1
        if self.scan_options.get("advanced_permutation_scan").get():
            tasks.append(self.permutation_scan(domain))
            total_tasks += 1
        if self.scan_options.get("advanced_alteration_scan").get():
            tasks.append(self.alteration_scan(domain))
            total_tasks += 1
        if self.scan_options.get("advanced_dnssec_check").get() and \
           self.config.get("advanced", {}).get("enable_dnssec_check", False):
            tasks.append(self.dnssec_check(domain))
            total_tasks += 1
        if self.scan_options.get("advanced_caa_enumeration").get() and \
           self.config.get("advanced", {}).get("enable_caa_enumeration", False):
            tasks.append(self.caa_enumeration(domain))
            total_tasks += 1
        if self.scan_options.get("advanced_takeover_detection").get() and \
           self.config.get("advanced", {}).get("enable_takeover_detection", False):
            tasks.append(self.takeover_detection(domain))
            total_tasks += 1

        # Active Techniques (to be run on discovered subdomains)
        active_tasks = []
        if self.scan_options.get("active_port_scan").get():
            active_tasks.append(self.port_scan())
        if self.scan_options.get("active_service_detection").get():
            active_tasks.append(self.service_detection())
        if self.scan_options.get("active_http_probe").get():
            active_tasks.append(self.http_probe())

        # Run basic and advanced tasks concurrently
        if tasks:
            for coro in asyncio.as_completed(tasks):
                if not self.is_running:
                    break
                await coro
                self.update_progress(increment=100 / total_tasks)

        # Run active techniques if any subdomains were found
        if active_tasks and self.discovered_subdomains:
            await asyncio.gather(*active_tasks)
            self.update_progress(increment=100 / len(active_tasks))

        self.status_var.set("Scan complete")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def update_progress(self, increment: float):
        new_value = self.progress_var.get() + increment
        self.progress_var.set(min(new_value, 100))
        self.root.update_idletasks()

    async def dns_bruteforce(self, domain):
        self.log_result(f"Starting DNS brute-force for {domain}")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.config.get("dns_servers", [])
        # Use wordlist from GUI if provided; otherwise fall back to config default using "custom"
        wordlist_path = self.wordlist_path.get().strip() or self.config.get("wordlists", {}).get("custom", "")
        wordlist = Path(wordlist_path)
        # Check that the wordlist exists and is a file
        if not wordlist.exists() or not wordlist.is_file():
            self.log_result(f"Wordlist not found or invalid: {wordlist}")
            return
        try:
            with open(wordlist) as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log_result(f"Error reading wordlist {wordlist}: {e}")
            return
        for word in words:
            if not self.is_running:
                break
            subdomain = f"{word}.{domain}"
            try:
                answers = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: resolver.resolve(subdomain, "A", lifetime=self.config["scanning"]["timeout"])
                )
                for rdata in answers:
                    self.add_subdomain(subdomain, str(rdata))
            except Exception:
                continue

    async def zone_transfer(self, domain):
        self.log_result(f"Attempting zone transfer for {domain}")
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            for ns in ns_records:
                ns_str = str(ns.target).rstrip(".")
                try:
                    xfr = dns.query.xfr(ns_str, domain, timeout=self.config["scanning"]["timeout"])
                    for zone in xfr:
                        for r in zone:
                            if r.rdtype == dns.rdatatype.A:
                                self.add_subdomain(domain, r.address)
                except Exception as e:
                    self.log_result(f"Zone transfer failed on {ns_str}: {e}")
        except Exception as e:
            self.log_result(f"NS lookup failed: {e}")

    async def wildcard_detection(self, domain):
        self.log_result(f"Performing wildcard detection on {domain}")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.config.get("dns_servers", [])
        random_sub = f"{random.randint(10000,99999)}.{domain}"
        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: resolver.resolve(random_sub, "A", lifetime=self.config["scanning"]["timeout"])
            )
            self.log_result(f"Wildcard DNS detected on {domain}. Responses: {[r.to_text() for r in answers]}")
        except Exception:
            self.log_result(f"No wildcard DNS found on {domain}")

    async def tld_enumeration(self, domain):
        self.log_result(f"Performing TLD enumeration for {domain}")
        extracted = tldextract.extract(domain)
        base = extracted.domain
        for tld in self.config.get("tlds", []):
            target = f"{base}.{tld}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = self.config.get("dns_servers", [])
                answers = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: resolver.resolve(target, "A", lifetime=self.config["scanning"]["timeout"])
                )
                for rdata in answers:
                    self.add_subdomain(target, str(rdata))
            except Exception:
                continue

    async def recursive_search(self, domain):
        self.log_result(f"Starting recursive subdomain search on {domain}")
        # For demo purposes, re-run dns_bruteforce (avoid infinite loops in production)
        await self.dns_bruteforce(domain)

    async def permutation_scan(self, domain):
        self.log_result(f"Starting permutation scan on {domain}")
        for prefix in self.config.get("subdomain_prefixes", []):
            subdomain = f"{prefix}.{domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = self.config.get("dns_servers", [])
                answers = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: resolver.resolve(subdomain, "A", lifetime=self.config["scanning"]["timeout"])
                )
                for rdata in answers:
                    self.add_subdomain(subdomain, str(rdata))
            except Exception:
                continue

    async def alteration_scan(self, domain):
        self.log_result(f"Starting alteration scan on {domain}")
        for i in range(len(domain)):
            if not domain[i].isalpha():
                continue
            altered = domain[:i] + chr((ord(domain[i]) - 96) % 26 + 97) + domain[i+1:]
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = self.config.get("dns_servers", [])
                answers = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: resolver.resolve(altered, "A", lifetime=self.config["scanning"]["timeout"])
                )
                for rdata in answers:
                    self.add_subdomain(altered, str(rdata))
            except Exception:
                continue

    async def dnssec_check(self, domain):
        self.log_result(f"Performing DNSSEC check on {domain}")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.config.get("dns_servers", [])
        try:
            answer = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: resolver.resolve(domain, "DNSKEY", lifetime=self.config["scanning"]["timeout"])
            )
            if answer.rrset:
                self.log_result(f"DNSSEC enabled for {domain}")
            else:
                self.log_result(f"DNSSEC not enabled for {domain}")
        except Exception as e:
            self.log_result(f"DNSSEC check failed for {domain}: {e}")

    async def caa_enumeration(self, domain):
        self.log_result(f"Enumerating CAA records for {domain}")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.config.get("dns_servers", [])
        try:
            answer = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: resolver.resolve(domain, "CAA", lifetime=self.config["scanning"]["timeout"])
            )
            for rdata in answer:
                self.log_result(f"CAA for {domain}: {rdata.to_text()}")
        except Exception as e:
            self.log_result(f"No CAA records found for {domain} or error: {e}")

    async def takeover_detection(self, domain):
        self.log_result(f"Starting subdomain takeover check for {domain}")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.config.get("dns_servers", [])
        try:
            cname_answer = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: resolver.resolve(domain, "CNAME", lifetime=self.config["scanning"]["timeout"])
            )
            for cname in cname_answer:
                cname_str = cname.target.to_text().lower()
                vulnerable_providers = ["aws", "heroku", "bitbucket", "github", "pages"]
                if any(provider in cname_str for provider in vulnerable_providers):
                    self.log_result(f"Potential subdomain takeover vulnerability: {domain} -> {cname_str}")
        except Exception as e:
            self.log_result(f"Takeover check skipped for {domain}: {e}")

    async def port_scan(self):
        self.log_result("Starting port scan on discovered subdomains")
        for subdomain in list(self.discovered_subdomains):
            try:
                ip = socket.gethostbyname(subdomain)
            except Exception:
                continue
            open_ports = []
            for port in self.config.get("ports", {}).get("common", []):
                if not self.is_running:
                    break
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda p=port: self.scan_port(ip, p)
                )
                if result:
                    open_ports.append(port)
            if open_ports:
                self.log_result(f"{subdomain} ({ip}) open ports: {open_ports}")

    def scan_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.config["scanning"]["timeout"])
                if s.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            return False
        return False

    async def service_detection(self):
        self.log_result("Starting service detection on discovered subdomains")
        for subdomain in list(self.discovered_subdomains):
            try:
                ip = socket.gethostbyname(subdomain)
            except Exception:
                continue
            for port in [80, 443]:
                banner = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda p=port: self.get_banner(ip, p)
                )
                if banner:
                    self.log_result(f"Service on {subdomain}:{port} -> {banner.strip()}")
                    
    def get_banner(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=self.config["scanning"]["timeout"]) as s:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode("utf-8", errors="ignore")
                return banner
        except Exception:
            return ""

    async def http_probe(self):
        self.log_result("Starting HTTP probe on discovered subdomains")
        for subdomain in list(self.discovered_subdomains):
            try:
                reader, writer = await asyncio.open_connection(subdomain, 80)
                writer.write(b"GET / HTTP/1.1\r\nHost: " + subdomain.encode() + b"\r\nConnection: close\r\n\r\n")
                await writer.drain()
                data = await reader.read(1024)
                if data:
                    self.log_result(f"HTTP response from {subdomain}: {data[:100].decode('utf-8', errors='ignore').strip()}...")
                writer.close()
                await writer.wait_closed()
            except Exception:
                continue

    def add_subdomain(self, subdomain, ip):
        if subdomain not in self.discovered_subdomains:
            self.discovered_subdomains.add(subdomain)
            self.log_result(f"Found: {subdomain} ({ip})")

    def log_result(self, message):
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        logging.info(message)

    def stop_scan(self):
        self.is_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Scan stopped")

    def save_results(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, "w") as f:
                f.write("\n".join(self.discovered_subdomains))
            messagebox.showinfo("Saved", f"Results saved to {filename}")

    def clear_results(self):
        self.results_text.delete("1.0", tk.END)
        self.discovered_subdomains.clear()

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedSubdomainScanner(root)
    root.mainloop()
