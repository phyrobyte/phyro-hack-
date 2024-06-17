# Phyro Hack+

Phyro Hack+ is a powerful CLI tool for network scanning, IP and firewall management, web testing, file transfer, and information gathering. This tool is intended for use by cybersecurity professionals for ethical hacking and penetration testing.

## Features

### Network Scanning
1. **Scan IP Range**: Scans a given IP range for devices.
2. **Port Scan**: Scans for open ports on a specified IP.
3. **Ping**: Pings a specified host.
4. **Traceroute**: Traces the path packets take to a destination.

### IP and Firewall Management
1. **Mask IP**: Changes the MAC address of the specified network interface.
2. **Lockdown**: Changes IP every 30 seconds, changes username and password, and locks down the firewall.
3. **Unlockdown**: Reverts the firewall settings and restores the original username.

### Web Testing
1. **SQL Injection Test**: Tests if a web application is vulnerable to SQL injection.
2. **XSS Test**: Tests if a web application is vulnerable to cross-site scripting.
3. **Directory Bruteforce**: Finds hidden directories on a web server.

### File Transfer
1. **FTP Send File**: Sends a file via FTP.
2. **SSH Send File**: Sends a file via SSH.

### Information Gathering
1. **DNS Lookup**: Resolves a domain name to an IP address.
2. **Reverse DNS Lookup**: Resolves an IP address to a domain name.
3. **WHOIS Lookup**: Retrieves registration information about a domain.
4. **Subdomain Scan**: Finds subdomains associated with a domain.
5. **Banner Grabbing**: Retrieves information about a service running on an open port.

## Installation

1. Clone the repository or download the files.
2. Navigate to the directory containing the files.
3. Run the following command to install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4. Alternatively, you can use the provided `install.bat` script:
    ```bat
    install.bat
    ```

## Usage

Run the script using Python and navigate through the menu to select the desired category and action. Here is an example of how to use the tool:

```bash
Run phyro_hack+1.0.0.py
