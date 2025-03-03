from colorama import init, Fore, Back, Style
import re
import requests
import subprocess
import sys
from os import system
import select
import termios
import tty
import time

# Initialize colorama
init()

YELLOW = 'YELLOW'
BLACK = 'BLACK'
RED = 'RED'
GREEN = 'GREEN'
BLUE = 'BLUE'
MAGENTA = 'MAGENTA'
CYAN = 'CYAN'
WHITE = 'WHITE'

max_subprocess = 200

logs_folder = 'ctfenum_logs'
system(f'mkdir {logs_folder} 2>/dev/null')

def printc(text, color=None, back_color=None):
    if color is not None:
        colored_text = getattr(Fore, color.upper(), Fore.RESET) + Style.BRIGHT + text
    else:
        colored_text = Style.RESET_ALL + text

    if back_color is not None:
        colored_text = getattr(Back, back_color.upper(), Back.RESET) + colored_text

    print(colored_text + Style.RESET_ALL)


# Prints a command output separator
def print_separator():
    printc('=' * 70, YELLOW)


def print_banner(port):
    print_separator()
    printc(f'[!] Attacking port {port}', YELLOW)  


def scan_for_dns(nmap_detail):
    detail = nmap_detail.splitlines()

    for line in detail:
        if 'Domain:' in line:
            results = re.findall(r'Domain: (.+)0\.', line)
            if results:
                parts = results[0].split('.')
                if len(parts) > 1:
                    dns = f'{parts[-2]}.{parts[-1]}'.strip()
                    return dns
        elif 'DNS:' in line:
            results = re.findall(r'DNS:.+\.(.+\..+)', line)
            if results:
                dns = results[0].strip()
                return dns
        elif 'DNS_Domain_Name' in line:
            results = re.findall(r'DNS_Domain_Name: (.*)\n', line)
            if results:
                dns = results[0].strip()
                return dns
        elif 'DNS_Tree_Name' in line:
            results = re.findall(r'DNS_Tree_Name: (.*)\n', line)
            if results:
                dns = results[0].strip()
                return dns
        elif ('ssl-cert' in line) and ('commonName' in line):
            results = re.findall(r'commonName=(.*)\n', line)
            if results:
                parts = results[0].split('.')
                if len(parts) > 1:
                    dns = f'{parts[-2]}.{parts[-1]}'.strip()
                    return dns
    return ''

def scan_hostname(nmap_detail):
    detail = nmap_detail.splitlines()

    for line in detail:
        if 'Host:' in line:
            results = re.findall(r'Host: (.+?);', line)
            if results:
                host = results[0].strip()
                return host
        elif 'NetBIOS:' in line:
            results = re.findall(r'NetBIOS name: (.+),', line)
            if results:
                host = results[0].strip()
                return host
        elif 'NetBIOS_Computer_Name' in line:
            results = re.findall(r'NetBIOS_Computer_Name: (.*)\n', line)
            if results:
                host = results[0].strip()
                return host
    return ''

def clean_hosts(ip, subdomain=None):
    with open('/etc/hosts', 'r') as file:
        data = file.readlines()

    line_to_delete = []

    for line in data:
        if len(line) < 5:
            line_to_delete.append(line)
            continue
        elif ip in line:
            line_to_delete.append(line)
            continue
        if subdomain:
            if subdomain in line:
                line_to_delete.append(line)

    for line in line_to_delete:
        try:
            data.remove(line)
        except:
            continue

    with open('/etc/hosts', 'w') as file:
        new_data = ''.join(data)
        file.write(new_data)


# Starts a list of subprocesses and then wait for them to finish
def launch_procs(procs):
    def is_input_available():
        return select.select([sys.stdin], [], [], 0)[0] != []

    def get_char():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

    while procs:
        try:
            running_procs = []
            
            # Launch subprocesses up to the maximum limit
            for proc in procs[:max_subprocess]:
                proc.start()
                running_procs.append(proc)
            
            # Monitor running processes and check for 's' key press
            while running_procs:
                # Check for 's' key press without blocking
                if is_input_available():
                    char = get_char()
                    if char.lower() == 's':
                        printc("\n[!] Skipping current module(s)...", YELLOW)
                        # Terminate all running processes
                        for p in running_procs:
                            if p.is_alive():
                                p.terminate()
                        break
                
                # Clean up finished processes
                running_procs = [p for p in running_procs if p.is_alive()]
                if not running_procs:
                    break
                    
                # Small sleep to prevent CPU overuse
                time.sleep(0.1)
            
            # Remove processed items from the queue
            procs = procs[max_subprocess:]
        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            for p in running_procs:
                if p.is_alive():
                    p.terminate()
            printc("\n[!] Interrupted by user", YELLOW)
            return []
        except Exception as e:
            continue
    return []


# Returns from a given username: an empty value, the same value, the reversed value
def get_usernames_esr(username):
    return ['', username, ''.join(reversed(username))]


# Version check utility
def check_version():
    banner = """
╔─────────────────────────────────────────────────────────────────────╗
│  ██████╗████████╗███████╗    ███████╗███╗   ██╗██╗   ██╗███╗   ███╗ │
│ ██╔════╝╚══██╔══╝██╔════╝    ██╔════╝████╗  ██║██║   ██║████╗ ████║ │
│ ██║        ██║   █████╗      █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║ │
│ ██║        ██║   ██╔══╝      ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║ │
│ ╚██████╗   ██║   ██║         ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║ │
│  ╚═════╝   ╚═╝   ╚═╝         ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝ │
╚─────────────────────────────────────────────────────────────────────╝
"""
    printc(banner, GREEN)

    current_version = '1.0.0'
    printc(f'Current version: {current_version}', GREEN)

def log(data, cmd, target='', tool='ctfenum'):
    thislog_path = f'{logs_folder}/{target.replace(".", "-")}'
    dir_cmd = f'mkdir -p {thislog_path} 2>/dev/null'
    system(dir_cmd)
    with open(f'./{thislog_path}/{tool}.txt', 'a') as file:
        file.write('*' * 20 + '\n' + cmd + '\n\n' + data + '\n')