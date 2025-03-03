import subprocess
import re
from mods.mod_utils import *
import socket
import shlex


def dns_print_banner():
    print_banner('53')
    print('[!] DNS')
    print('[+] Subdomains added to /etc/hosts:')
    print_separator()


def validate_domain(domain):
    """Validate if a string is a valid domain name."""
    if not domain:
        return False
    # Basic domain validation regex
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def parse_dns_record(line, domain):
    """Parse a DNS record line and extract relevant information."""
    if not line or not domain:
        return None
        
    # Skip comment lines and empty lines
    if line.startswith(';') or not line.strip():
        return None
        
    parts = line.split()
    if len(parts) < 4:  # Minimum parts for a valid record
        return None
        
    record_name = parts[0].rstrip('.')
    record_type = parts[3]
    
    # Only process certain record types
    if record_type not in ['A', 'AAAA', 'CNAME', 'MX', 'NS']:
        return None
        
    # Ensure the record is related to our domain
    if not record_name.endswith(domain):
        return None
        
    return record_name


def dns_add_subdomains(ip, subdomains):
    if not subdomains or len(subdomains) < 1:
        return
        
    # Filter out empty or None values and validate domains
    subdomains = [s.strip() for s in subdomains if s and s.strip() and validate_domain(s.strip())]
    if not subdomains:
        return

    try:
        # Read current hosts file
        with open('/etc/hosts', 'r') as file:
            lines = file.readlines()

        # Remove empty lines and normalize existing lines
        lines = [line.strip() for line in lines if line.strip()]
        
        # Remove any existing lines with our IP or subdomains
        new_lines = []
        existing_domains = set()
        for line in lines:
            parts = line.split()
            if len(parts) < 2:  # Skip invalid lines
                continue
            line_ip = parts[0]
            line_domains = parts[1:]
            
            # Validate IP address
            try:
                socket.inet_aton(line_ip)
            except socket.error:
                continue
            
            if line_ip == ip:
                # Save existing domains for this IP
                existing_domains.update(d for d in line_domains if validate_domain(d))
                continue
            
            # Check if line contains any of our subdomains
            if not any(subdomain in line_domains for subdomain in subdomains):
                new_lines.append(line)
        
        # Combine existing and new domains, removing duplicates
        all_domains = set(subdomains) | existing_domains
        
        # Add our new line with all domains
        new_lines.append(f'{ip} {" ".join(sorted(all_domains))}')
        
        # Write back to hosts file with proper formatting
        with open('/etc/hosts', 'w') as file:
            file.write('\n'.join(new_lines) + '\n')
            
    except Exception as e:
        printc(f'[-] Error modifying hosts file: {str(e)}', RED)
        return False
        
    return True


def handle_dns(ip, dns=None):
    """Handle DNS enumeration including zone transfers."""
    if not dns:
        dns_print_banner()
        printc('[-] No domain specified', RED)
        print('[!] If you find a FQDN you can use this command to look for other subdomains:')
        print(f'[!] dig axfr @{ip} your.domain.tld')
        return

    if not validate_domain(dns):
        printc(f'[-] Invalid domain name: {dns}', RED)
        return

    # Validate IP address
    try:
        socket.inet_aton(ip)
    except socket.error:
        printc(f'[-] Invalid IP address: {ip}', RED)
        return

    # Construct and escape the dig command
    cmd_dns = f'dig axfr @{ip} {shlex.quote(dns)}'

    try:
        output = subprocess.check_output(
            cmd_dns, 
            shell=True, 
            stderr=subprocess.STDOUT, 
            universal_newlines=True,
            timeout=30  # Add timeout
        )

        if 'Transfer failed' in output or 'communications error' in output:
            printc('[-] Zone transfer failed - Transfer might be forbidden', RED)
            return

        if output and 'SERVER:' in output:
            subdomains = set()
            
            # Process each line of output
            for line in output.splitlines():
                subdomain = parse_dns_record(line, dns)
                if subdomain:
                    subdomains.add(subdomain)

            if subdomains:
                if dns_add_subdomains(ip, subdomains):
                    dns_print_banner()
                    print(f'[!] {cmd_dns}')
                    print('\n[+] Found subdomains:')
                    for subdomain in sorted(subdomains):
                        printc(f'    {subdomain}', GREEN)

                    log('\n'.join(sorted(subdomains)), cmd_dns, ip, 'dig')
                else:
                    printc('[-] Failed to update hosts file', RED)
            else:
                printc('[-] No subdomains found', YELLOW)

    except subprocess.TimeoutExpired:
        printc('[-] DNS query timed out', RED)
    except subprocess.CalledProcessError as e:
        printc(f'[-] Error running dig command: {str(e)}', RED)
    except Exception as e:
        printc(f'[-] Unexpected error: {str(e)}', RED)