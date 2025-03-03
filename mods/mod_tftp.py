import tftpy
from mods.mod_utils import *
import tempfile
import os
import socket
import hashlib
import random
import string


def generate_safe_temp_content(length=32):
    """Generate safe content for testing uploads."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def get_file_hash(filepath):
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def safe_file_read(filepath):
    """Safely read a file with size limit."""
    max_size = 1024 * 1024  # 1MB limit
    try:
        if os.path.getsize(filepath) > max_size:
            return f"File too large (>{max_size/1024:.0f}KB)"
        with open(filepath, 'r') as f:
            return f.read()
    except UnicodeDecodeError:
        return "[Binary file]"
    except Exception as e:
        return f"Error reading file: {str(e)}"


def handle_tftp(ip):
    """Handle TFTP enumeration including file upload/download testing."""
    try:
        # Validate IP
        try:
            socket.inet_aton(ip)
        except socket.error:
            printc(f'[-] Invalid IP address: {ip}', RED)
            return

        print_banner('69')
        print('[+] Testing TFTP server')
        
        # Create a temporary file with known content for upload testing
        test_content = generate_safe_temp_content()
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp:
            temp.write(test_content)
            temp_path = temp.name
            
        client = tftpy.TftpClient(ip, 69, options={'blksize': 512})
        
        # Test upload capabilities
        print('\n[+] Testing upload capabilities:')
        upload_tests = [
            ('test.txt', 'Simple text file'),
            ('../test.txt', 'Path traversal attempt'),
            ('/etc/test.txt', 'Absolute path attempt'),
            ('test.txt;touch evil.txt', 'Command injection attempt')
        ]
        
        for test_file, description in upload_tests:
            try:
                client.upload(test_file, temp_path)
                if ';' in test_file or '../' in test_file or test_file.startswith('/'):
                    printc(f'[!] WARNING: Server allowed potentially dangerous upload: {test_file}', RED)
                else:
                    printc(f'[+] Upload successful: {test_file}', GREEN)
            except Exception as e:
                print(f'[-] Upload failed for {test_file}: {str(e)}')
            
        # Test download capabilities
        print('\n[+] Testing download capabilities:')
        interesting_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hostname',
            '/etc/hosts',
            'test.txt',
            '../../../etc/passwd',  # Path traversal attempt
            'boot.ini',  # Windows files
            'windows/win.ini'
        ]
        
        for filename in interesting_files:
            try:
                out_path = os.path.join(tempfile.gettempdir(), 
                                      'tftp_' + os.path.basename(filename))
                client.download(filename, out_path)
                
                # Verify download was successful
                if os.path.exists(out_path):
                    content = safe_file_read(out_path)
                    if '../' in filename or filename.startswith('/'):
                        printc(f'[!] WARNING: Path traversal might be possible: {filename}', RED)
                    printc(f'[+] Successfully downloaded {filename}:', GREEN)
                    print(content)
                    
                    # Calculate and display file hash
                    file_hash = get_file_hash(out_path)
                    print(f'    SHA256: {file_hash}')
                    
                    os.remove(out_path)
            except Exception as e:
                if 'Access violation' in str(e):
                    print(f'[-] Access denied: {filename}')
                elif 'File not found' in str(e):
                    print(f'[-] File not found: {filename}')
                else:
                    print(f'[-] Failed to download {filename}: {str(e)}')
                
        # Cleanup
        try:
            os.remove(temp_path)
        except:
            pass
        
        print('\n[+] TFTP Security Assessment:')
        security_warnings = []
        
        # Check if uploads are allowed
        if any('Upload successful' in line for line in globals()['_last_output']):
            security_warnings.append('Server allows file uploads')
        
        # Check if path traversal is possible
        if any('Path traversal might be possible' in line for line in globals()['_last_output']):
            security_warnings.append('Path traversal might be possible')
            
        # Print security warnings
        if security_warnings:
            print('\n[!] Security concerns:')
            for warning in security_warnings:
                printc(f'    - {warning}', YELLOW)
        else:
            printc('[+] No major security concerns detected', GREEN)
        
    except Exception as e:
        printc(f'[-] TFTP Error: {str(e)}', RED)
        return
        
    log("TFTP enumeration completed", "Testing file upload and common file downloads", ip, "tftp")