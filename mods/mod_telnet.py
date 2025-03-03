import socket
import telnetlib
import re
from mods.mod_utils import *
import time
import ssl


def test_telnet_auth(ip, port, username, password, timeout=5):
    """Test Telnet authentication with given credentials."""
    try:
        tn = telnetlib.Telnet(ip, port, timeout=timeout)
        
        # Try to detect login prompt
        index, match, text = tn.expect([b'login:', b'username:', b'user:'], timeout=timeout)
        if index >= 0:
            tn.write(username.encode() + b'\n')
            index, match, text = tn.expect([b'password:', b'pass:'], timeout=timeout)
            if index >= 0:
                tn.write(password.encode() + b'\n')
                # Check for successful login
                response = tn.read_until(b'$', timeout=2)
                if b'incorrect' not in response.lower() and b'failed' not in response.lower():
                    return True, response
        tn.close()
    except:
        pass
    return False, None


def check_telnet_security(ip, port):
    """Check for common Telnet security issues."""
    security_warnings = []
    try:
        # Try connecting without credentials
        tn = telnetlib.Telnet(ip, port, timeout=5)
        banner = tn.read_until(b'\n', timeout=2)
        
        # Check for version disclosure in banner
        if any(v.encode() in banner.lower() for v in ['ver', 'version']):
            security_warnings.append('Server discloses version information')
            
        # Check for clear text transmission
        test_string = b'test_security_check'
        tn.write(test_string)
        if test_string in tn.read_until(test_string, timeout=2):
            security_warnings.append('Clear text data transmission')
            
        # Check for command availability before login
        common_commands = [b'help', b'system', b'show', b'set']
        for cmd in common_commands:
            tn.write(cmd + b'\n')
            response = tn.read_until(b'\n', timeout=1)
            if not any(err in response.lower() for err in [b'login', b'denied', b'error']):
                security_warnings.append(f'Command {cmd.decode()} might be available before login')
                
        tn.close()
    except:
        pass
        
    return security_warnings


def explore_telnet_system(tn):
    """Explore system information after successful login."""
    common_commands = [
        'uname -a',
        'cat /etc/issue',
        'cat /etc/passwd',
        'id',
        'who',
        'w',
        'last',
        'ps aux'
    ]
    
    results = []
    for cmd in common_commands:
        try:
            tn.write(cmd.encode() + b'\n')
            response = tn.read_until(b'$', timeout=2)
            if response and not b'denied' in response.lower():
                results.append(f'Command: {cmd}\nOutput: {response.decode()}')
        except:
            continue
            
    return results


def handle_telnet(ip, port=23):
    """Handle Telnet enumeration and security testing."""
    try:
        # Validate IP
        try:
            socket.inet_aton(ip)
        except socket.error:
            printc(f'[-] Invalid IP address: {ip}', RED)
            return
            
        print_banner(str(port))
        print('[!] TELNET')
        print('[!] Testing Telnet security...\n')
        
        # Check basic connectivity
        try:
            socket.create_connection((ip, port), timeout=5)
        except socket.error:
            printc(f'[-] Could not connect to {ip}:{port}', RED)
            return
            
        # Check for security issues
        security_warnings = check_telnet_security(ip, port)
        
        if security_warnings:
            print('[!] Security concerns found:')
            for warning in security_warnings:
                printc(f'    - {warning}', YELLOW)
        
        # Test common credentials
        print('\n[+] Testing common credentials:')
        common_creds = [
            ('root', 'root'),
            ('admin', 'admin'),
            ('administrator', 'password'),
            ('telnet', 'telnet'),
            ('user', 'password'),
            ('default', 'default')
        ]
        
        for username, password in common_creds:
            success, response = test_telnet_auth(ip, port, username, password)
            if success:
                printc(f'[!] Valid credentials found: {username}:{password}', GREEN)
                
                # Try to explore system
                try:
                    tn = telnetlib.Telnet(ip, port, timeout=5)
                    tn.read_until(b'login:', timeout=5)
                    tn.write(username.encode() + b'\n')
                    tn.read_until(b'password:', timeout=5)
                    tn.write(password.encode() + b'\n')
                    
                    print('\n[+] Exploring system:')
                    results = explore_telnet_system(tn)
                    for result in results:
                        print(result)
                        
                    tn.close()
                except:
                    pass
                    
        # Log findings
        log_data = [
            f'Security Warnings: {", ".join(security_warnings)}',
            'Credentials tested: ' + ', '.join(f'{u}:{p}' for u, p in common_creds)
        ]
        log('\n'.join(log_data), '', ip, 'telnet')
        
    except Exception as e:
        printc(f'[-] Error: {str(e)}', RED)
        return