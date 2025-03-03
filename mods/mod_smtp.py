import smtplib
import socket
import ssl
from mods.mod_utils import *
import re
import multiprocessing


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

        print_banner(str(port))
        print('[+] SMTP Server Information:')

        procs = []

        def run_smtp_enum():
            try:
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
                
                for cmd, users in commands.items():
                    print(f'\n[+] Testing {cmd} command:')
                    for user in users:
                        result = test_smtp_command(smtp, cmd, user)
                        if result:
                            printc(f'[+] {cmd} {user}: {result}', GREEN)
                            log(f'{cmd} {user}: {result}', '', ip, 'smtp')
                        else:
                            print(f'[-] {cmd} {user}: Command failed or not supported')
                
                smtp.quit()
            except Exception as e:
                printc(f'[-] SMTP Error: {str(e)}', RED)

        # Create process for SMTP enumeration
        smtp_proc = multiprocessing.Process(target=run_smtp_enum)
        procs.append(smtp_proc)

        # Launch all processes with skip functionality
        procs = launch_procs(procs)

    except Exception as e:
        printc(f'[-] Error: {str(e)}', RED)
        return

    log(f"SMTP enumeration completed on {ip}:{port}", "Python smtplib", ip, "smtp")
