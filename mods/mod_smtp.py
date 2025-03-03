import smtplib
import socket
from mods.mod_utils import *

def handle_smtp(ip, port):
    try:
        # Create SMTP connection
        smtp = smtplib.SMTP(timeout=10)
        smtp.connect(ip, port)
        
        # Get server info
        server_info = smtp.ehlo()
        if server_info[0] == 250:
            print_banner(str(port))
            print('[+] SMTP Server Information:')
            for line in server_info[1].decode().split('\n'):
                print(f'[+] {line}')
            
            # Try VRFY command with common usernames
            print('\n[+] Testing VRFY command with common usernames:')
            common_users = ['root', 'admin', 'administrator', 'postmaster', 'mail', 'www-data']
            for user in common_users:
                try:
                    code, message = smtp.verify(user)
                    if code == 250:
                        printc(f'[+] Valid user found: {user}', GREEN)
                    elif code == 252:
                        printc(f'[+] User {user} may exist (response: 252)', BLUE)
                except:
                    pass
                    
        smtp.quit()
        
    except Exception as e:
        printc(f'[-] SMTP Error: {str(e)}', RED)
        return

    log(f"SMTP enumeration completed on {ip}:{port}", "Python smtplib", ip, "smtp")
