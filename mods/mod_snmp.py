from pysnmp.hlapi import *
from mods.mod_utils import *

def snmp_walk(ip, community, oid_root):
    results = []
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                             CommunityData(community),
                             UdpTransportTarget((ip, 161)),
                             ContextData(),
                             ObjectType(ObjectIdentity(oid_root)),
                             lexicographicMode=False):

        if errorIndication:
            break
        elif errorStatus:
            break
        else:
            for varBind in varBinds:
                results.append(f'{varBind[0]} = {varBind[1]}')
    return results

def handle_snmp(ip):
    # Common community strings to try
    communities = ['public', 'private', 'manager', 'admin', 'cisco', 'community']
    
    print_banner('161')
    print('[+] Testing SNMP communities')
    
    found_communities = []
    
    # First find valid communities
    for community in communities:
        try:
            # Create SNMP GET request for sysDescr
            iterator = getNext(
                SnmpEngine(),
                CommunityData(community, mpModel=0),  # SNMPv1
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1'))  # sysDescr
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if not errorIndication and not errorStatus:
                printc(f'[+] Found valid community string: {community}', GREEN)
                found_communities.append(community)
                
        except Exception:
            continue
    
    # For each valid community, enumerate information
    for community in found_communities:
        print(f'\n[+] Enumerating with community: {community}')
        
        # Common OID roots to walk
        oid_roots = {
            'System': '1.3.6.1.2.1.1',
            'Interfaces': '1.3.6.1.2.1.2.2',
            'IP Addresses': '1.3.6.1.2.1.4.20',
            'Running Processes': '1.3.6.1.2.1.25.4.2',
            'Installed Software': '1.3.6.1.2.1.25.6.3.1',
            'Storage Units': '1.3.6.1.2.1.25.2.3.1',
            'System Users': '1.3.6.1.4.1.77.1.2.25',
            'TCP Local Ports': '1.3.6.1.2.1.6.13.1.3'
        }
        
        for section, oid in oid_roots.items():
            try:
                results = snmp_walk(ip, community, oid)
                if results:
                    print(f'\n[+] {section}:')
                    for result in results:
                        print(f'    {result}')
            except Exception:
                continue
                
    if found_communities:
        log("SNMP enumeration completed", f"Valid communities found: {', '.join(found_communities)}", ip, "snmp")
    else:
        log("SNMP enumeration completed", "No valid communities found", ip, "snmp")