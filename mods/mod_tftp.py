import tftpy
from mods.mod_utils import *
import tempfile
import os

def handle_tftp(ip):
    try:
        print_banner('69')
        print('[+] Testing TFTP server')
        
        # Create a temporary file to test upload
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp:
            temp.write('test')
            temp_path = temp.name
            
        client = tftpy.TftpClient(ip, 69)
        
        # Try to upload the test file
        try:
            client.upload('test.txt', temp_path)
            printc('[+] File upload successful - Server allows writes!', GREEN)
        except:
            print('[-] File upload failed - Write access denied')
            
        # Try to download some common files
        common_files = ['/etc/hostname', '/etc/passwd', '/etc/shadow', 'test.txt']
        for filename in common_files:
            try:
                out_path = os.path.join(tempfile.gettempdir(), os.path.basename(filename))
                client.download(filename, out_path)
                with open(out_path, 'r') as f:
                    content = f.read()
                printc(f'[+] Successfully downloaded {filename}:', GREEN)
                print(content)
                os.remove(out_path)
            except:
                print(f'[-] Failed to download {filename}')
                
        # Cleanup
        os.remove(temp_path)
        
    except Exception as e:
        printc(f'[-] TFTP Error: {str(e)}', RED)
        return
        
    log("TFTP enumeration completed", "Testing file upload and common file downloads", ip, "tftp")