import os
import random
import socket
import subprocess
import time
import requests
from ftplib import FTP, error_perm
import whois
from scapy.all import ARP, Ether, srp
from termcolor import colored, cprint
import paramiko
import sys
import ctypes

# ASCII Art
def print_ascii_art():
    art = """
    

       .__                           .__                   __                
______ |  |__ ___.__._______  ____   |  |__ _____    ____ |  | __    .__     
\____ \|  |  <   |  |\_  __ \/  _ \  |  |  \\__  \ _/ ___\|  |/ /  __|  |___ 
|  |_> >   Y  \___  | |  | \(  <_> ) |   Y  \/ __ \\  \___|    <  /__    __/ 
|   __/|___|  / ____| |__|   \____/  |___|  (____  /\___  >__|_ \    |__|    
|__|        \/\/                          \/     \/     \/     \/            



                          Phyro Hack+
    """
    cprint(art, 'green')

# Check if running as admin/root
def check_admin():
    if os.name == 'nt':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False
        if not is_admin:
            cprint("This script must be run as an administrator.", 'red')
            # Re-run the script with admin rights
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
            sys.exit()
    else:
        if os.geteuid() != 0:
            cprint("This script must be run as root. Re-running with sudo...", 'red')
            os.execvp("sudo", ["sudo"] + ["python3"] + sys.argv)
            sys.exit()

# Clear screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Error Handling Helper
def handle_error(error):
    error_message = f"An error occurred: {str(error)}"
    if isinstance(error, socket.gaierror):
        error_message += " - Network address not found. Please check the IP or domain."
    elif isinstance(error, socket.timeout):
        error_message += " - The operation timed out. The server may be down or unreachable."
    elif isinstance(error, ConnectionRefusedError):
        error_message += " - Connection refused. The server may be blocking the connection or it may be offline."
    elif isinstance(error, error_perm):
        error_message += " - Permission denied. Incorrect username or password for FTP."
    elif isinstance(error, paramiko.ssh_exception.AuthenticationException):
        error_message += " - Authentication failed. Incorrect SSH username or password."
    elif isinstance(error, paramiko.ssh_exception.SSHException):
        error_message += " - Failed to establish an SSH connection."
    elif 'whois' in str(error) and 'module' in str(error):
        error_message += " - Failed to perform WHOIS lookup. Ensure 'python-whois' package is installed."
    else:
        error_message += " - Unknown error occurred."
    cprint(error_message, 'red')

# Network Scanning
def scan_ip(ip_range):
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
        return devices
    except Exception as e:
        handle_error(e)
        return []

def port_scan(target_ip, port_range):
    open_ports = []
    try:
        for port in range(port_range[0], port_range[1] + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
    except Exception as e:
        handle_error(e)
        return []

def ping(host):
    try:
        response = subprocess.run(["ping", "-c", "4", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return response.stdout.decode()
    except Exception as e:
        handle_error(e)
        return None

def traceroute(host):
    try:
        result = subprocess.run(["traceroute", host], stdout=subprocess.PIPE)
        return result.stdout.decode()
    except Exception as e:
        handle_error(e)
        return None

# IP and Firewall Management
def mask_ip(interface):
    try:
        new_mac = "02:00:00:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
        )
        os.system(f"ifconfig {interface} down")
        os.system(f"ifconfig {interface} hw ether {new_mac}")
        os.system(f"ifconfig {interface} up")
        open("/tmp/ip_masked", "w").close()  # Create a file to indicate IP is masked
        return new_mac
    except Exception as e:
        handle_error(e)
        return None

def change_ip(interface):
    try:
        new_ip = "192.168.1." + str(random.randint(2, 254))
        os.system(f"ifconfig {interface} {new_ip}")
        return new_ip
    except Exception as e:
        handle_error(e)
        return None

def change_username_password(old_username, new_username, new_password):
    try:
        os.system(f"usermod -l {new_username} {old_username}")
        os.system(f"echo '{new_username}:{new_password}' | chpasswd")
        return new_username
    except Exception as e:
        handle_error(e)
        return None

def lockdown_firewall():
    try:
        os.system("iptables -P INPUT DROP")
        os.system("iptables -P FORWARD DROP")
        os.system("iptables -P OUTPUT ACCEPT")
        os.system("iptables -A INPUT -i lo -j ACCEPT")
        os.system("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    except Exception as e:
        handle_error(e)

def unlockdown_firewall():
    try:
        os.system("iptables -P INPUT ACCEPT")
        os.system("iptables -P FORWARD ACCEPT")
        os.system("iptables -P OUTPUT ACCEPT")
        os.system("iptables -F")
    except Exception as e:
        handle_error(e)

def lockdown(interface, old_username, new_username, new_password):
    change_username_password(old_username, new_username, new_password)
    lockdown_firewall()
    while True:
        new_ip = change_ip(interface)
        if new_ip:
            cprint(f"IP changed to: {new_ip}", 'yellow')
        time.sleep(30)

def unlockdown(old_username, new_username, new_password):
    unlockdown_firewall()
    change_username_password(new_username, old_username, new_password)
    cprint("System unlocked and original settings restored", 'green')

# Web Testing
def sql_injection_test(url):
    try:
        payloads = ["' OR '1'='1", "' OR '1'='1' --", '" OR "1"="1', '" OR "1"="1" --']
        vulnerable = False
        for payload in payloads:
            full_url = f"{url}{payload}"
            response = requests.get(full_url)
            if "error" not in response.text:
                vulnerable = True
                break
        return vulnerable
    except Exception as e:
        handle_error(e)
        return None

def xss_test(url):
    try:
        payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
        vulnerable = False
        for payload in payloads:
            full_url = f"{url}{payload}"
            response = requests.get(full_url)
            if payload in response.text:
                vulnerable = True
                break
        return vulnerable
    except Exception as e:
        handle_error(e)
        return None

def directory_bruteforce(url, wordlist_file="directories.txt"):
    try:
        with open(wordlist_file, "r") as file:
            directories = file.read().splitlines()
        discovered_directories = []
        for directory in directories:
            full_url = f"{url}/{directory}"
            response = requests.get(full_url)
            if response.status_code == 200:
                discovered_directories.append(full_url)
        return discovered_directories
    except Exception as e:
        handle_error(e)
        return []

# File Transfer
def ftp_send_file(host, username, password, local_file, remote_file):
    try:
        ftp = FTP(host)
        ftp.login(user=username, passwd=password)
        with open(local_file, 'rb') as file:
            ftp.storbinary(f'STOR {remote_file}', file)
        ftp.quit()
        cprint(f"File {local_file} sent to {host} as {remote_file}", 'green')
    except Exception as e:
        handle_error(e)

def ssh_send_file(host, username, password, local_file, remote_file):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        sftp = ssh.open_sftp()
        sftp.put(local_file, remote_file)
        sftp.close()
        ssh.close()
        cprint(f"File {local_file} sent to {host} as {remote_file}", 'green')
    except Exception as e:
        handle_error(e)

# Information Gathering
def dns_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        handle_error(e)
        return None

def reverse_dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)
    except Exception as e:
        handle_error(e)
        return None

def whois_lookup(domain):
    try:
        return whois.whois(domain)
    except Exception as e:
        handle_error(e)
        return None

def subdomain_scan(domain, subdomains_file="subdomains.txt"):
    try:
        with open(subdomains_file, "r") as file:
            subdomains = file.read().splitlines()
        discovered_subdomains = []
        for subdomain in subdomains:
            url = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(url)
                discovered_subdomains.append(url)
            except socket.gaierror:
                pass
        return discovered_subdomains
    except Exception as e:
        handle_error(e)
        return []

def banner_grabbing(ip, port):
    try:
        sock = socket.socket()
        sock.connect((ip, port))
        sock.send(b'HEAD / HTTP/1.1\n\n')
        banner = sock.recv(1024)
        sock.close()
        return banner.decode().strip()
    except Exception as e:
        handle_error(e)
        return None

def main_menu():
    while True:
        clear_screen()
        print_ascii_art()
        cprint("\nMain Menu:", 'blue', attrs=['bold'])
        cprint("1. Network Scanning", 'cyan')
        cprint("2. IP and Firewall Management", 'cyan')
        cprint("3. Web Testing", 'cyan')
        cprint("4. File Transfer", 'cyan')
        cprint("5. Information Gathering", 'cyan')
        cprint("6. Exit", 'cyan')
        choice = input(colored("Select a category: ", 'yellow'))

        if choice == '1':
            network_scanning_menu()
        elif choice == '2':
            ip_firewall_menu()
        elif choice == '3':
            web_testing_menu()
        elif choice == '4':
            file_transfer_menu()
        elif choice == '5':
            info_gathering_menu()
        elif choice == '6':
            cprint("Exiting...", 'red')
            break
        else:
            cprint("Invalid choice. Please try again.", 'red')

def network_scanning_menu():
    while True:
        clear_screen()
        print_ascii_art()
        cprint("\nNetwork Scanning Menu:", 'blue', attrs=['bold'])
        cprint("1. Scan IP Range", 'cyan')
        cprint("2. Port Scan", 'cyan')
        cprint("3. Ping", 'cyan')
        cprint("4. Traceroute", 'cyan')
        cprint("5. Back", 'cyan')
        choice = input(colored("Select an action: ", 'yellow'))

        if choice == '1':
            ip_range = input(colored("Enter IP range (e.g., 192.168.1.0/24): ", 'yellow'))
            devices = scan_ip(ip_range)
            for device in devices:
                cprint(f"IP: {device['ip']}, MAC: {device['mac']}", 'green')
        elif choice == '2':
            ip = input(colored("Enter IP address: ", 'yellow'))
            port_start = int(input(colored("Enter start port: ", 'yellow')))
            port_end = int(input(colored("Enter end port: ", 'yellow')))
            open_ports = port_scan(ip, (port_start, port_end))
            cprint(f"Open ports: {open_ports}", 'green')
        elif choice == '3':
            host = input(colored("Enter host to ping: ", 'yellow'))
            response = ping(host)
            cprint(response, 'green')
        elif choice == '4':
            host = input(colored("Enter host to traceroute: ", 'yellow'))
            trace = traceroute(host)
            cprint(trace, 'green')
        elif choice == '5':
            break
        else:
            cprint("Invalid choice. Please try again.", 'red')
        input(colored("\nPress Enter to continue...", 'yellow'))

def ip_firewall_menu():
    while True:
        clear_screen()
        print_ascii_art()
        cprint("\nIP and Firewall Management Menu:", 'blue', attrs=['bold'])
        cprint("1. Mask IP", 'cyan')
        cprint("2. Lockdown", 'cyan')
        cprint("3. Unlockdown", 'cyan')
        cprint("4. Back", 'cyan')
        choice = input(colored("Select an action: ", 'yellow'))

        if choice == '1':
            interface = input(colored("Enter network interface (e.g., eth0): ", 'yellow'))
            new_mac = mask_ip(interface)
            cprint(f"New MAC address: {new_mac}", 'green')
        elif choice == '2':
            interface = input(colored("Enter network interface (e.g., eth0): ", 'yellow'))
            old_username = input(colored("Enter old username: ", 'yellow'))
            new_username = input(colored("Enter new username: ", 'yellow'))
            new_password = input(colored("Enter new password: ", 'yellow'))
            lockdown(interface, old_username, new_username, new_password)
        elif choice == '3':
            old_username = input(colored("Enter old username: ", 'yellow'))
            new_username = input(colored("Enter new username: ", 'yellow'))
            new_password = input(colored("Enter new password: ", 'yellow'))
            unlockdown(old_username, new_username, new_password)
        elif choice == '4':
            break
        else:
            cprint("Invalid choice. Please try again.", 'red')
        input(colored("\nPress Enter to continue...", 'yellow'))

def web_testing_menu():
    while True:
        clear_screen()
        print_ascii_art()
        cprint("\nWeb Testing Menu:", 'blue', attrs=['bold'])
        cprint("1. SQL Injection Test", 'cyan')
        cprint("2. XSS Test", 'cyan')
        cprint("3. Directory Bruteforce", 'cyan')
        cprint("4. Back", 'cyan')
        choice = input(colored("Select an action: ", 'yellow'))

        if choice == '1':
            url = input(colored("Enter URL to test for SQL injection: ", 'yellow'))
            vulnerable = sql_injection_test(url)
            cprint(f"Vulnerable: {vulnerable}", 'green')
        elif choice == '2':
            url = input(colored("Enter URL to test for XSS: ", 'yellow'))
            vulnerable = xss_test(url)
            cprint(f"Vulnerable: {vulnerable}", 'green')
        elif choice == '3':
            url = input(colored("Enter URL: ", 'yellow'))
            wordlist_file = input(colored("Enter path to wordlist file: ", 'yellow'))
            directories = directory_bruteforce(url, wordlist_file)
            for directory in directories:
                cprint(directory, 'green')
        elif choice == '4':
            break
        else:
            cprint("Invalid choice. Please try again.", 'red')
        input(colored("\nPress Enter to continue...", 'yellow'))

def file_transfer_menu():
    while True:
        clear_screen()
        print_ascii_art()
        cprint("\nFile Transfer Menu:", 'blue', attrs=['bold'])
        cprint("1. FTP Send File", 'cyan')
        cprint("2. SSH Send File", 'cyan')
        cprint("3. Back", 'cyan')
        choice = input(colored("Select an action: ", 'yellow'))

        if choice == '1':
            host = input(colored("Enter FTP host: ", 'yellow'))
            username = input(colored("Enter FTP username: ", 'yellow'))
            password = input(colored("Enter FTP password: ", 'yellow'))
            local_file = input(colored("Enter path to local file: ", 'yellow'))
            remote_file = input(colored("Enter path to remote file: ", 'yellow'))
            ftp_send_file(host, username, password, local_file, remote_file)
        elif choice == '2':
            host = input(colored("Enter SSH host: ", 'yellow'))
            username = input(colored("Enter SSH username: ", 'yellow'))
            password = input(colored("Enter SSH password: ", 'yellow'))
            local_file = input(colored("Enter path to local file: ", 'yellow'))
            remote_file = input(colored("Enter path to remote file: ", 'yellow'))
            ssh_send_file(host, username, password, local_file, remote_file)
        elif choice == '3':
            break
        else:
            cprint("Invalid choice. Please try again.", 'red')
        input(colored("\nPress Enter to continue...", 'yellow'))

def info_gathering_menu():
    while True:
        clear_screen()
        print_ascii_art()
        cprint("\nInformation Gathering Menu:", 'blue', attrs=['bold'])
        cprint("1. DNS Lookup", 'cyan')
        cprint("2. Reverse DNS Lookup", 'cyan')
        cprint("3. WHOIS Lookup", 'cyan')
        cprint("4. Subdomain Scan", 'cyan')
        cprint("5. Banner Grabbing", 'cyan')
        cprint("6. Back", 'cyan')
        choice = input(colored("Select an action: ", 'yellow'))

        if choice == '1':
            domain = input(colored("Enter domain: ", 'yellow'))
            ip = dns_lookup(domain)
            cprint(f"IP address: {ip}", 'green')
        elif choice == '2':
            ip = input(colored("Enter IP address: ", 'yellow'))
            domain = reverse_dns_lookup(ip)
            cprint(f"Domain: {domain}", 'green')
        elif choice == '3':
            domain = input(colored("Enter domain: ", 'yellow'))
            info = whois_lookup(domain)
            cprint(info, 'green')
        elif choice == '4':
            domain = input(colored("Enter domain: ", 'yellow'))
            subdomains_file = input(colored("Enter path to subdomains file: ", 'yellow'))
            subdomains = subdomain_scan(domain, subdomains_file)
            for subdomain in subdomains:
                cprint(subdomain, 'green')
        elif choice == '5':
            ip = input(colored("Enter IP address: ", 'yellow'))
            port = int(input(colored("Enter port: ", 'yellow')))
            banner = banner_grabbing(ip, port)
            cprint(f"Banner: {banner}", 'green')
        elif choice == '6':
            break
        else:
            cprint("Invalid choice. Please try again.", 'red')
        input(colored("\nPress Enter to continue...", 'yellow'))

if __name__ == "__main__":
    check_admin()
    print_ascii_art()
    cprint("REMINDER: DO NOT PERFORM ANY ACTIONS WITH THIS APP BEFORE YOU MASK YOUR IP ADDRESS", 'red')
    
    main_menu()
