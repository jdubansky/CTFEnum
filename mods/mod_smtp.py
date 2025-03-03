import smtplib
import socket
import ssl
from mods.mod_utils import *
import re


def validate_email(email):
    """Validate email address format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def test_smtp_command(smtp, command, *args):
    """Safely test an SMTP command."""
    try:
        method = getattr(smtp, command.lower(), None)
        if method:
            return method(*args)
    except (smtplib.SMTPException, socket.error) as e:
        return None
    return None


def handle_smtp(ip, port):
    """Handle SMTP enumeration including server info and user enumeration."""
    try:
        # Validate IP
        try:
            socket.inet_aton(ip)
        except socket.error:
            printc(f'[-] Invalid IP address: {ip}', RED)
            return

        # Create SMTP connection with timeout
        smtp = smtplib.SMTP(timeout=10)
        
        # Try connecting with STARTTLS first
        try:
            smtp.connect(ip, port)
            if test_smtp_command(smtp, 'starttls'):
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                smtp.starttls(context=context)
                printc('[+] Successfully upgraded to TLS connection', GREEN)
        except Exception:
            # If STARTTLS fails, try regular connection
            smtp = smtplib.SMTP(timeout=10)
            smtp.connect(ip, port)
        
        print_banner(str(port))
        print('[+] SMTP Server Information:')
        
        # Get server info
        try:
            server_info = smtp.ehlo()
            if server_info[0] == 250:
                for line in server_info[1].decode().split('\n'):
                    print(f'[+] {line}')
            else:
                # Try HELO if EHLO fails
                server_info = smtp.helo()
                if server_info[0] == 250:
                    print(f'[+] {server_info[0]} {server_info[1].decode()}')
        except Exception as e:
            printc(f'[-] Failed to get server info: {str(e)}', RED)
        
        # Test various SMTP commands
        print('\n[+] Testing SMTP commands:')
        commands = {
            'VRFY': ['root', 'admin', 'administrator', 'postmaster', 'mail', 'www-data'],
            'EXPN': ['root', 'admin', 'postmaster'],
            'RCPT': ['postmaster@localhost', 'root@localhost']
        }
        
        for command, test_values in commands.items():
            print(f'\n[+] Testing {command} command:')
            for value in test_values:
                try:
                    if command == 'RCPT':
                        # For RCPT, we need to send MAIL FROM first
                        smtp.docmd('MAIL FROM:', '<test@test.com>')
                        code, message = smtp.docmd('RCPT TO:', f'<{value}>')
                    else:
                        code, message = smtp.docmd(command, value)
                        
                    if code == 250:
                        printc(f'[+] Valid recipient: {value}', GREEN)
                    elif code == 252:
                        printc(f'[+] Recipient may exist: {value} (response: 252)', BLUE)
                    elif code == 550 or code == 551:
                        print(f'[-] Invalid recipient: {value}')
                    else:
                        print(f'[?] Unknown response for {value}: {code} {message.decode()}')
                except Exception:
                    continue
                    
        # Test for open relay
        print('\n[+] Testing for open relay:')
        try:
            test_from = 'test@test.com'
            test_to = 'test@test.com'
            
            smtp.docmd('MAIL FROM:', f'<{test_from}>')
            code, message = smtp.docmd('RCPT TO:', f'<{test_to}>')
            
            if code == 250:
                printc('[!] WARNING: Server might be an open relay!', RED)
            else:
                print('[-] Server is not an open relay')
        except Exception:
            print('[-] Could not test for open relay')
                    
        smtp.quit()
        
    except Exception as e:
        printc(f'[-] SMTP Error: {str(e)}', RED)
        return

    log(f"SMTP enumeration completed on {ip}:{port}", "Python smtplib", ip, "smtp")
