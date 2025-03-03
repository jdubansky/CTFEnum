import imaplib
import socket
from mods.mod_utils import *

def handle_imap(ip, port):
    try:
        # Create connection
        imap = imaplib.IMAP4(ip, port)
        
        # Get server capabilities and version
        print_banner(str(port))
        print('[+] IMAP Server Information:')
        
        # Get server greeting (contains version usually)
        if hasattr(imap, 'welcome'):
            printc(f'[+] Server greeting: {imap.welcome.decode()}', GREEN)
            
        # Get capabilities
        typ, capabilities = imap.capability()
        if typ == 'OK':
            print('[+] Server capabilities:')
            for cap in capabilities[0].decode().split():
                print(f'    {cap}')
                
        # Try some basic auth methods
        print('\n[+] Supported authentication methods:')
        if 'AUTH=PLAIN' in capabilities[0].decode():
            print('    PLAIN')
        if 'AUTH=LOGIN' in capabilities[0].decode():
            print('    LOGIN')
        if 'AUTH=CRAM-MD5' in capabilities[0].decode():
            print('    CRAM-MD5')
            
        imap.logout()
        
    except Exception as e:
        printc(f'[-] IMAP Error: {str(e)}', RED)
        return
        
    log(f"IMAP enumeration completed on {ip}:{port}", "Python imaplib", ip, "imap")
