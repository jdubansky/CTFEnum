import imaplib
import socket
import ssl
from mods.mod_utils import *


def test_imap_auth(imap, username, password):
    """Test IMAP authentication with given credentials."""
    try:
        imap.login(username, password)
        return True
    except (imaplib.IMAP4.error, socket.error):
        return False


def handle_imap(ip, port):
    """Handle IMAP enumeration including server info and security testing."""
    try:
        # Validate IP
        try:
            socket.inet_aton(ip)
        except socket.error:
            printc(f'[-] Invalid IP address: {ip}', RED)
            return

        print_banner(str(port))
        print('[+] IMAP Server Information:')
        
        # Try SSL/TLS connection first
        ssl_success = False
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            imap = imaplib.IMAP4_SSL(ip, port, ssl_context=context)
            ssl_success = True
            printc('[+] Successfully established SSL/TLS connection', GREEN)
        except Exception:
            # Fall back to regular connection
            try:
                imap = imaplib.IMAP4(ip, port)
            except Exception as e:
                printc(f'[-] Failed to connect: {str(e)}', RED)
                return
        
        # Get server greeting
        if hasattr(imap, 'welcome'):
            try:
                welcome = imap.welcome.decode()
                printc(f'[+] Server greeting: {welcome}', GREEN)
                
                # Check for version disclosure
                if any(v in welcome.lower() for v in ['ver', 'version']):
                    printc('[!] WARNING: Server discloses version information', YELLOW)
            except:
                pass
            
        # Get capabilities
        try:
            typ, capabilities = imap.capability()
            if typ == 'OK':
                print('\n[+] Server capabilities:')
                caps = capabilities[0].decode().split()
                for cap in caps:
                    print(f'    {cap}')
                    
                # Security checks
                security_warnings = []
                if not ssl_success and not any(c.startswith('STARTTLS') for c in caps):
                    security_warnings.append('No SSL/TLS or STARTTLS support')
                if any(c.startswith('AUTH=PLAIN') for c in caps):
                    security_warnings.append('Supports plaintext authentication')
                if not any(c.startswith('AUTH=') for c in caps):
                    security_warnings.append('No authentication methods advertised')
                    
                # Print security warnings
                if security_warnings:
                    print('\n[!] Security concerns:')
                    for warning in security_warnings:
                        printc(f'    - {warning}', YELLOW)
                
                # Print authentication methods
                print('\n[+] Supported authentication methods:')
                auth_methods = [c for c in caps if c.startswith('AUTH=')]
                if auth_methods:
                    for method in auth_methods:
                        print(f'    {method}')
                else:
                    print('    No explicit AUTH methods advertised')
                    
                # Test for anonymous login
                print('\n[+] Testing anonymous access:')
                if test_imap_auth(imap, 'anonymous', 'anonymous'):
                    printc('[!] WARNING: Anonymous login is allowed!', RED)
                else:
                    print('[-] Anonymous login not allowed')
                    
                # Test common credentials
                print('\n[+] Testing common credentials:')
                common_creds = [
                    ('admin', 'admin'),
                    ('root', 'root'),
                    ('test', 'test')
                ]
                for username, password in common_creds:
                    if test_imap_auth(imap, username, password):
                        printc(f'[!] WARNING: Found valid credentials - {username}:{password}', RED)
                        
        except Exception as e:
            printc(f'[-] Error getting capabilities: {str(e)}', RED)
            
        try:
            imap.logout()
        except:
            pass
        
    except Exception as e:
        printc(f'[-] IMAP Error: {str(e)}', RED)
        return
        
    log(f"IMAP enumeration completed on {ip}:{port}", "Python imaplib", ip, "imap")
