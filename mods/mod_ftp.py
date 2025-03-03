from ftplib import FTP, error_perm, error_temp
import socket
import ssl
from mods.mod_utils import *
import multiprocessing
from time import sleep
import os
import tempfile
import re


# List of common FTP users
common_ftp_users = [
    'admin','user','ftp','test','guest','root','ftpuser','operator','support','backup','developer'
]


# List of common FTP passwords
common_ftp_passwords = [
    'password','123456','admin','12345','qwerty','1234','password1','abc123','letmein','password123','changeme','welcome','ftp123'
]

def validate_credentials(username, password):
    """Validate FTP credentials format."""
    if not username or not password:
        return False
    # Check for common injection patterns
    dangerous_chars = ['|', ';', '&', '$', '>', '<', '`', '\\']
    return not any(c in username + password for c in dangerous_chars)


def test_ftp_features(ftp):
    """Test FTP server features and security settings."""
    features = []
    security_warnings = []
    
    try:
        # Get server features
        resp = ftp.sendcmd('FEAT')
        if resp.startswith('211-'):
            features = resp.split('\n')[1:-1]
            features = [f.strip() for f in features]
    except:
        pass
        
    # Check security features
    if not any('TLS' in f for f in features):
        security_warnings.append('No TLS/SSL support advertised')
    if any('SITE EXEC' in f for f in features):
        security_warnings.append('SITE EXEC command enabled (potential RCE)')
    if any('CHMOD' in f for f in features):
        security_warnings.append('CHMOD command enabled')
        
    return features, security_warnings


def test_ftp_write_access(ftp):
    """Test if we have write access to the FTP server."""
    try:
        # Create a temporary file
        temp_content = "test file - please delete"
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp:
            temp.write(temp_content)
            temp_path = temp.name
            
        # Try to upload it
        with open(temp_path, 'rb') as f:
            try:
                ftp.storbinary('STOR test_write_access.txt', f)
                printc('[!] WARNING: Write access is enabled!', RED)
                # Try to delete it
                try:
                    ftp.delete('test_write_access.txt')
                except:
                    printc('[!] WARNING: Uploaded test file could not be deleted', RED)
                return True
            except:
                return False
            finally:
                os.remove(temp_path)
    except:
        return False


def explore_ftp_directory(ftp, path='.', depth=0, max_depth=3):
    """Recursively explore FTP directory structure."""
    if depth > max_depth:
        return
        
    try:
        # List current directory
        files = []
        ftp.dir(path, files.append)
        
        # Look for interesting files
        interesting_patterns = [
            r'password', r'backup', r'config', r'\.conf$', r'\.ini$',
            r'\.db$', r'\.sql$', r'\.env$', r'\.htpasswd$'
        ]
        
        for f in files:
            # Parse the file listing
            parts = f.split()
            if len(parts) < 8:
                continue
                
            perms, _, owner, group, size, month, day, name = parts[0:8]
            
            # Check permissions
            if 'w' in perms[7:]:  # Check if world-writable
                printc(f'[!] WARNING: World-writable file found: {path}/{name}', YELLOW)
                
            # Check for interesting files
            for pattern in interesting_patterns:
                if re.search(pattern, name.lower()):
                    printc(f'[+] Interesting file found: {path}/{name}', GREEN)
                    
            # Recursively explore directories
            if perms.startswith('d'):
                try:
                    explore_ftp_directory(ftp, f'{path}/{name}', depth + 1, max_depth)
                except:
                    pass
    except:
        pass


def ftp_connect(server, port, username, password):
    """Attempt to connect to FTP server and perform security checks."""
    try:
        # Validate inputs
        try:
            socket.inet_aton(server)
        except socket.error:
            printc(f'[-] Invalid IP address: {server}', RED)
            return
            
        if not validate_credentials(username, password):
            printc(f'[-] Invalid credentials format', RED)
            return
            
        # Try FTPS (FTP over TLS) first
        try:
            ftp = FTP_TLS()
            ftp.connect(server, int(port))
            ftp.auth()
            ftp.login(user=username, passwd=password)
            printc('[+] Successfully established FTP over TLS connection', GREEN)
        except:
            # Fall back to regular FTP
            ftp = FTP()
            ftp.connect(server, int(port))
            ftp.login(user=username, passwd=password)

        # Print success banner
        print_banner(port)
        printc(f'[+] FTP Credentials "{username}:{password}"', BLUE)
        
        # Get server info
        print('\n[+] Server Information:')
        print(f'    Welcome: {ftp.getwelcome()}')
        
        # Check server features and security
        features, warnings = test_ftp_features(ftp)
        if features:
            print('\n[+] Server Features:')
            for feature in features:
                print(f'    {feature}')
                
        if warnings:
            print('\n[!] Security Concerns:')
            for warning in warnings:
                printc(f'    - {warning}', YELLOW)
                
        # Test write access
        print('\n[+] Testing write access:')
        write_access = test_ftp_write_access(ftp)
        
        # Explore directory structure
        print('\n[+] Directory Listing:')
        explore_ftp_directory(ftp)

        # Log findings
        log_data = [
            f'FTP Credentials: {username}:{password}',
            f'Security Warnings: {", ".join(warnings)}',
            f'Write Access: {write_access}'
        ]
        log('\n'.join(log_data), '', server, 'ftp')

        ftp.quit()
    except Exception as e:
        return
    

def ftp_brute(ip, port):
    """Perform FTP brute force with rate limiting and smart wordlists."""
    tested_creds = set()  # Use set for faster lookups
    max_processes = 5  # Limit concurrent processes
    active_processes = []

    # Combine username variations
    usernames = set(common_ftp_users)
    for user in common_ftp_users:
        usernames.update(get_usernames_esr(user))

    # Generate credential pairs
    for username in usernames:
        for password in common_ftp_passwords + [username]:  # Add username as password
            if (username, password) not in tested_creds:
                tested_creds.add((username, password))
                
                # Manage active processes
                while len(active_processes) >= max_processes:
                    active_processes = [p for p in active_processes if p.is_alive()]
                    sleep(0.1)
                
                process = multiprocessing.Process(
                    target=ftp_connect, 
                    args=(ip, port, username, password)
                )
                process.start()
                active_processes.append(process)
                sleep(0.1)  # Rate limiting
    
    # Wait for remaining processes
    for process in active_processes:
        process.join()


def print_this_banner(port):
    print_banner(port)  
    print('[!] FTP')
    print('''[!] If the FTP server does not lists the content, try these commands:
    ftp:>passive
    ftp:>bin
    ftp:>ls -la
    
[!] Common security checks:
    1. Anonymous access
    2. Weak credentials
    3. Write permissions
    4. Sensitive files
    5. TLS/SSL support
    6. Directory traversal''')


def handle_ftp(target, port, nmap_detail):
    """Handle FTP enumeration and security testing."""
    print_this_banner(port)
    
    if 'ftp-anon' in nmap_detail:
        printc('[+] Server has anonymous login enabled', GREEN)
        username = 'anonymous'
        if 'Logged in as ftp' in nmap_detail:
            username = 'ftp'
        if '20/tcp   closed ftp-data' in nmap_detail:
            printc('[-] Service is exposed but might be unavailable', RED)
        ftp_connect(target, port, username, 'anonymous@example.com')
    else:
        printc('[!] Testing common credentials in background', YELLOW)
        ftp_brute(target, port)