![This is an alt text.](https://github.com/dineshpathro90/subfuck/blob/main/Screenshot.png "This is a sample image.")


# Advanced Subdomain Scanner

###### This repository contains an advanced subdomain scanner implemented in Python using Tkinter for the GUI and asyncio for asynchronous operations. The scanner supports various techniques for discovering subdomains and enumerating DNS records.

## Features

* DNS Brute-force: Scan for subdomains using a wordlist.
* Zone Transfer: Attempt zone transfers to enumerate subdomains.
* Wildcard Detection: Detect wildcard DNS entries.
* TLD Enumeration: Enumerate subdomains across different TLDs.
* Recursive Search: Perform recursive subdomain searches.
* Permutation Scan: Scan for subdomains using common permutations.
* Alteration Scan: Scan for subdomains using character alterations.
* DNSSEC Check: Check for DNSSEC records.
* CAA Enumeration: Enumerate CAA (Certification Authority Authorization) records.
* Subdomain Takeover Detection: Detect potential subdomain takeover vulnerabilities.
* Port Scan: Scan open ports on discovered subdomains.
* Service Detection: Detect services running on open ports.
* HTTP Probe: Probe HTTP services on discovered subdomains.


## Requirements

* Python 3.7+
* Tkinter (usually included with Python)
* asyncio
* dnspython
* tldextract

### Install the required Python packages using pip:

```
pip install dnspython tldextract
```

## Usage

### Clone the repository:

```
git clone https://github.com/dineshpathro90/subfuck.git &&
cd subfuck
```
### Run the scanner:

```
python3 subfuck.py
```

### Configure the scanner:

* The scanner uses a configuration file (config.json) to set various parameters such as DNS servers, wordlists, and scan options.

* You can customize the configuration file to suit your needs.

### Use the GUI:

1. Enter the target domain in the "Domain" input field.
2. Select the wordlist file using the "Browse" button.
3. Choose the scan options you want to enable.
4. Click "Start Scan" to begin the scan.
5. View the results in the "Results" tab.
6. Save or clear the results using the respective buttons.

### Configuration

#### The config.json file allows you to configure various settings for the scanner. Here is an example configuration:

```
{
    "scanning": {
      "timeout": 5,
      "max_threads": 50,
      "max_retries": 3,
      "delay": 0.1
    },
    "dns_servers": [
      "8.8.8.8",
      "8.8.4.4",
      "1.1.1.1",
      "1.0.0.1",
      "9.9.9.9",
      "208.67.222.222"
    ],
    "ports": {
      "common": [80, 443, 8080, 8443],
      "extended": [21, 22, 25, 53, 110, 123, 143, 445, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 6379],
      "full": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    },
    "subdomain_prefixes": ["www", "mail", "ftp", "test", "dev", "api", "ns1", "ns2"],
    "tlds": ["com", "net", "org", "info", "biz", "io"],
    "advanced": {
      "enable_dnssec_check": true,
      "enable_caa_enumeration": true,
      "enable_takeover_detection": true
    }
  }
  
```
