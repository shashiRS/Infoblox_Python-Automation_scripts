#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Shashikala R S"
__email__  = "srs@infoblox.com"

#############################################################################
# Grid Set up required:                                                     # 
#  1.SA grid + HA + M1                                                      #
#  2. Licenses : Grid,DNS,RPZ license,                                      #
#############################################################################
import os
import re
import config
import pytest
import unittest
import logging
import json
from time import sleep
import ib_utils.ib_NIOS as ib_NIOS
import shlex
from time import sleep
from subprocess import Popen, PIPE
import pexpect
import paramiko
from scapy import *
from scapy.utils import RawPcapReader
from scapy.all import *
import shutil
from ib_utils.start_stop_logs import log_action as log
from ib_utils.file_content_validation import log_validation as logv
from ib_utils.Bgp_and_OSPF_new import install_bird_package as birdv
# from ib_utils import user_input as usr_input
logging.basicConfig(format='%(asctime)s - %(name)s(%(process)d) - %(levelname)s - %(message)s',filename="RFE_10176.log" ,level=logging.DEBUG,filemode='w')

def set_restart_anycast_on():
    print("setting restart_anycast_with_dns_restart on")
    child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
    child.logfile=sys.stdout
    child.expect('password:')
    child.sendline('infoblox')
    child.expect('Infoblox >')
    child.sendline('set restart_anycast_with_dns_restart on')
    child.expect('>')
    child.close()
 
def set_restart_anycast_off():
    print("setting restart_anycast_with_dns_restart off")
    child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
    child.logfile=sys.stdout
    child.expect('password:')
    child.sendline('infoblox')
    child.expect('Infoblox >')
    child.sendline('set restart_anycast_with_dns_restart off')
    child.expect('>')
    child.close() 

def dns_restart_services():
    print("DNS Restart Services")
    grid =  ib_NIOS.wapi_request('GET', object_type="grid", grid_vip=config.grid_vip)
    ref = json.loads(grid)[0]['_ref']
    data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
    request_restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),grid_vip=config.grid_vip)
    sleep(120)

def dns_restart_services_normally():
    print("DNS Restart Services Normally")
    grid =  ib_NIOS.wapi_request('GET', object_type="grid", grid_vip=config.grid_vip)
    ref = json.loads(grid)[0]['_ref']
    data= {"member_order" : "SIMULTANEOUSLY","restart_option":"RESTART_IF_NEEDED","service_option": "ALL"}
    request_restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),grid_vip=config.grid_vip)
    sleep(120)
    
    
def dns_start_services():
    print("DNS Start Services")
    get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns")
    print(get_ref)
    res = json.loads(get_ref)
    for i in res:
        data = {"enable_dns": True}
        response = ib_NIOS.wapi_request('PUT', ref=i['_ref'], fields=json.dumps(data))
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: DNS Start Services")
                assert False
            else:
                print("Success: DNS Start Services")
                assert True
    sleep(80)
    
    
def dns_stop_services():
    print("DNS stop Services")
    get_ref = ib_NIOS.wapi_request('GET', object_type="member:dns")
    print(get_ref)
    res = json.loads(get_ref)
    for i in res:
        data = {"enable_dns": False}
        response = ib_NIOS.wapi_request('PUT', ref=i['_ref'], fields=json.dumps(data))
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: DNS Start Services")
                assert False
            else:
                print("Success: DNS Start Services")
                assert True
    sleep(80)
    
def ospf_ipv4_configuration():
    get_ref = ib_NIOS.wapi_request('GET', object_type='member?_return_fields=additional_ip_list')
    print(get_ref)
    for ref in json.loads(get_ref):

        data={"ospf_list": [ {
                    "area_id": "0.0.0.12",
                    "area_type": "STANDARD",
                    "authentication_type": "NONE",
                    "auto_calc_cost_enabled": True,
                    "cost": 1,
                    "dead_interval": 40,
                    "enable_bfd": False,
                    "hello_interval": 10,
                    "interface": "LAN_HA",
                    "is_ipv4": True,
                    "key_id": 1,
                    "retransmit_interval": 5,
                    "transmit_delay": 1
                }
            ]}
        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: OSPF for advertising")
                assert False
            else:
                print("Success: OSPF for advertising")
                assert True
                
def anycast_ipv4_configuration():

    get_ref = ib_NIOS.wapi_request('GET', object_type='member?_return_fields=additional_ip_list')
    print(get_ref)
    for ref in json.loads(get_ref):
        data={"additional_ip_list": [
            {
                "anycast": True,
                "enable_bgp": False,
                "enable_ospf": True,
                "interface": "LOOPBACK",
                "ipv4_network_setting": {
                    "address": "1.3.3.3",
                    "dscp": 0,
                    "primary": False,
                    "subnet_mask": "255.255.255.255",
                    "use_dscp": False
                }
            }
        ]}
        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Anycast configuration")
                assert False
            else:
                print("Success: Anycast configuration")
                assert True
         
    get_ref = ib_NIOS.wapi_request('GET', object_type='member:dns?_return_fields=additional_ip_list_struct')
    print(get_ref)
    for ref in json.loads(get_ref):
        data={"additional_ip_list_struct": [{
                "ip_address": "1.3.3.3"
            }]}
        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        sleep(30)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Anycast configuration for member DNS")
                assert False
            else:
                print("Success: Anycast configuration for member DNS")
                assert True
                
                
def ospf_for_advertising_ipv6():
    get_ref = ib_NIOS.wapi_request('GET', object_type='member?_return_fields=additional_ip_list')
    print(get_ref)
    for ref in json.loads(get_ref):

        data={"ospf_list": [
            {
                "area_id": "0.0.0.12",
                "area_type": "STANDARD",
                "authentication_type": "NONE",
                "auto_calc_cost_enabled": True,
                "cost": 1,
                "dead_interval": 40,
                "enable_bfd": False,
                "hello_interval": 10,
                "interface": "LAN_HA",
                "is_ipv4": True,
                "key_id": 1,
                "retransmit_interval": 5,
                "transmit_delay": 1
            },
            {
                "area_id": "0.0.0.12",
                "area_type": "STANDARD",
                "authentication_type": "NONE",
                "auto_calc_cost_enabled": True,
                "cost": 1,
                "dead_interval": 40,
                "enable_bfd": False,
                "hello_interval": 10,
                "interface": "LAN_HA",
                "is_ipv4": False,
                "key_id": 1,
                "retransmit_interval": 5,
                "transmit_delay": 1
            }
        ]}

        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        sleep(30)
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: OSPF for advertising")
                assert False
            else:
                print("Success: OSPF for advertising")
                assert True
             
def anycast_ipv6_configuration():
    get_ref = ib_NIOS.wapi_request('GET', object_type='member?_return_fields=additional_ip_list')
    print(get_ref)
    for ref in json.loads(get_ref):
        data={"config_addr_type": "BOTH",
        "additional_ip_list": [
            {
                "anycast": True,
                "enable_bgp": False,
                "enable_ospf": True,
                "interface": "LOOPBACK",
                "ipv4_network_setting": {
                    "address": "1.3.3.3",
                    "dscp": 0,
                    "primary": False,
                    "subnet_mask": "255.255.255.255",
                    "use_dscp": False
                }
            },
            {
                "anycast": True,
                "enable_bgp": False,
                "enable_ospf": True,
                "interface": "LOOPBACK",
                "ipv6_network_setting": {
                    "cidr_prefix": 128,
                    "dscp": 0,
                    "enabled": True,
                    "primary": False,
                    "use_dscp": False,
                    "virtual_ip": "3333::3331"
                }
            }
        ]}

        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        sleep(30)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Anycast configuration")
                assert False
            else:
                print("Success: Anycast configuration")
                assert True
                
        
    get_ref = ib_NIOS.wapi_request('GET', object_type='member:dns?_return_fields=additional_ip_list_struct')

    print(get_ref)
    for ref in json.loads(get_ref):
        data={"use_lan_ipv6_port":True,
        "additional_ip_list_struct": [
            {
                "ip_address": "1.3.3.3"
            },
            {
                "ip_address": "3333::3331"
            }
        ]}
        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        sleep(30)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Anycast configuration for member DNS")
                assert False
            else:
                print("Success: Anycast configuration for member DNS")
                assert True


def bgp_configuration():
    get_ref = ib_NIOS.wapi_request('GET', object_type='member?_return_fields=bgp_as')
    print(get_ref)
    for ref in json.loads(get_ref):

        data={"bgp_as": [
            {
                "as": 12,
                "holddown": 16,
                "keepalive": 4,
                "link_detect": False,
                "neighbors": [
                    {
                        "authentication_mode": "NONE",
                        "enable_bfd": False,
                        "interface": "LAN_HA",
                        "multihop": False,
                        "multihop_ttl": 255,
                        "neighbor_ip": "10.35.152.8",
                        "remote_as": 12
                    }
                ]
            }
        ]}
        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: BGP for advertising")
                assert False
            else:
                print("Success: BGP for advertising")
                assert True
                
def anycast_bgp_ipv4_configuration():

    get_ref = ib_NIOS.wapi_request('GET', object_type='member?_return_fields=additional_ip_list')
    print(get_ref)
    for ref in json.loads(get_ref):
        data={"additional_ip_list": [
            {
                "anycast": True,
                "enable_bgp": True,
                "enable_ospf": True,
                "interface": "LOOPBACK",
                "ipv4_network_setting": {
                    "address": "1.3.3.3",
                    "dscp": 0,
                    "primary": False,
                    "subnet_mask": "255.255.255.255",
                    "use_dscp": False
                }
            },
            {
                "anycast": True,
                "enable_bgp": False,
                "enable_ospf": True,
                "interface": "LOOPBACK",
                "ipv6_network_setting": {
                    "cidr_prefix": 128,
                    "dscp": 0,
                    "enabled": True,
                    "primary": False,
                    "use_dscp": False,
                    "virtual_ip": "3333::3331"
                }
            }
        ]}
        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Anycast configuration")
                assert False
            else:
                print("Success: Anycast configuration")
                assert True 

def anycast_bgp_ipv6_configuration():
    get_ref = ib_NIOS.wapi_request('GET', object_type='member?_return_fields=additional_ip_list')
    print(get_ref)
    for ref in json.loads(get_ref):
        data={"additional_ip_list": [
            {
                "anycast": True,
                "enable_bgp": True,
                "enable_ospf": True,
                "interface": "LOOPBACK",
                "ipv4_network_setting": {
                    "address": "1.3.3.3",
                    "dscp": 0,
                    "primary": False,
                    "subnet_mask": "255.255.255.255",
                    "use_dscp": False
                }
            },
            {
                "anycast": True,
                "enable_bgp": True,
                "enable_ospf": True,
                "interface": "LOOPBACK",
                "ipv6_network_setting": {
                    "cidr_prefix": 128,
                    "dscp": 0,
                    "enabled": True,
                    "primary": False,
                    "use_dscp": False,
                    "virtual_ip": "3333::3331"
                }
            }
        ]}
        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Anycast configuration")
                assert False
            else:
                print("Success: Anycast configuration")
                assert True


def abnormally_kill_named():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
    mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
    client.connect(config.grid_vip, username='root', pkey = mykey)
    data="killall named"
    stdin, stdout, stderr = client.exec_command(data)
    stdout=stdout.read()
    print("=========Killall=========")
    print(stdout)


def validate_the_uptime_during_restarts ():
    args = "sshpass -p 'infoblox' ssh -o StrictHostKeyChecking=no admin@"+config.client_vip
    args=shlex.split(args)
    child1 = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    child1.stdin.write("show ospf neighbor \n")
    flag=0
    output = child1.communicate()
    print(output)
    if 'Progressive change .*s ago' in output:
        assert True
    else:
        assert False
    
 
def subscriber_start_services():
    print("Subscriber Start Services")
    get_ref = ib_NIOS.wapi_request('GET', object_type="member:parentalcontrol")
    print(get_ref)
    res = json.loads(get_ref)
    for i in res:
        data = {"enable_service": True}
        response = ib_NIOS.wapi_request('PUT', ref=i['_ref'], fields=json.dumps(data))
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Subscriber Start Services")
                assert False
            else:
                print("Success: Subscriber Start Services")
                assert True
    sleep(10)


def subscriber_stop_services():
    print("Subscriber Start Services")
    get_ref = ib_NIOS.wapi_request('GET', object_type="member:parentalcontrol")
    print(get_ref)
    res = json.loads(get_ref)
    for i in res:
        data = {"enable_service": False}
        response = ib_NIOS.wapi_request('PUT', ref=i['_ref'], fields=json.dumps(data))
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Subscriber Start Services")
                assert False
            else:
                print("Success: Subscriber Start Services")
                assert True
    sleep(10)
    

def check_process_response_when_SS_ON():
    flag_bgp=False
    flag_osfp=False
    flag_zebra=False
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
    mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
    client.connect(config.grid_vip, username='root', pkey = mykey)
    data="pgrep bgp\n"
    stdin, stdout, stderr = client.exec_command(data)
    stdout=stdout.read()
    print(len(stdout))
    
    if len(stdout)==0:
        flag_bgp=True
        client.close()
        
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
    mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
    client.connect(config.grid_vip, username='root', pkey = mykey)
    data="pgrep ospf\n"
    stdin, stdout, stderr = client.exec_command(data)
    stdout=stdout.read()
    print(stdout)
    
    if len(stdout)==0:
        flag_osfp=True
        client.close()   

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
    mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
    client.connect(config.grid_vip, username='root', pkey = mykey)
    data="pgrep zebra\n"
    stdin, stdout, stderr = client.exec_command(data)
    stdout=stdout.read()
    print(stdout)
    
    if len(stdout)==0:
        flag_zebra=True
        client.close()   
    print(flag_bgp,flag_osfp,flag_zebra)
    if flag_bgp==True and flag_osfp==True and flag_zebra==True:
        assert True
    else:
        assert False


def check_process_response_id_when_SS_ON():
    flag_bgp=True
    flag_osfp=True
    flag_zebra=True
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
    mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
    client.connect(config.grid_vip, username='root', pkey = mykey)
    data="pgrep bgp\n"
    stdin, stdout, stderr = client.exec_command(data)
    stdout=stdout.read()
    print(len(stdout))
    
    if len(stdout)==0:
        flag_bgp=False
        client.close()
        
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
    mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
    client.connect(config.grid_vip, username='root', pkey = mykey)
    data="pgrep ospf\n"
    stdin, stdout, stderr = client.exec_command(data)
    stdout=stdout.read()
    print(stdout)
    
    if len(stdout)==0:
        flag_osfp=False
        client.close()   

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
    mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
    client.connect(config.grid_vip, username='root', pkey = mykey)
    data="pgrep zebra\n"
    stdin, stdout, stderr = client.exec_command(data)
    stdout=stdout.read()
    print(stdout)
    
    if len(stdout)==0:
        flag_zebra=False
        client.close()   
        
    print(flag_bgp,flag_osfp,flag_zebra) 
    if flag_bgp==True and flag_osfp==True and flag_zebra==True:
        assert True
    else:
        assert False

def reboot():

    print("Reboot the appliance")
    child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@10.35.20.192')
    child.logfile=sys.stdout
    child.expect('password:')
    child.sendline('infoblox')
    child.expect('Infoblox >')
    child.sendline('reboot')
    child.expect('y or n')
    child.sendline('y')
    sleep(60)

def changes_require_a_service_set_true():
    get_ref = ib_NIOS.wapi_request('GET', object_type='member:dns?_return_fields=additional_ip_list_struct')
    print(get_ref)
    for ref in json.loads(get_ref):
        data={"allow_recursive_query":True}
        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Changes require a service restart")
                assert False
            else:
                print("Success: Changes require a service restart")
                assert True


def changes_require_a_service_set_false():
    get_ref = ib_NIOS.wapi_request('GET', object_type='member:dns?_return_fields=additional_ip_list_struct')
    print(get_ref)
    for ref in json.loads(get_ref):
        data={"allow_recursive_query":False}
        response = ib_NIOS.wapi_request('PUT', ref=ref['_ref'], fields=json.dumps(data),grid_vip=config.grid_vip)
        print(response)
        
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Changes require a service restart")
                assert False
            else:
                print("Success: Changes require a service restart")
                assert True                   
class RFE_10176(unittest.TestCase):
    
    @pytest.mark.run(order=1)
    def test_000_create_New_AuthZone(self):
        dns_start_services()
        for i in range(1000):
            data = {"fqdn": "zone"+str(i)+".com","grid_primary": [{"name": config.grid_member_fqdn,"stealth":False}]}
            response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data))
            print(response)
            
            if type(response) == tuple:
                if response[0]==400 or response[0]==401 or response[0]==401:
                    print("Failure: Create A new Zone")
                    assert False
                else:
                    print("Success: Create A new Zone")
                    assert True
         
        print("Restart DHCP Services")
        grid =  ib_NIOS.wapi_request('GET', object_type="grid", grid_vip=config.grid_vip)
        ref = json.loads(grid)[0]['_ref']
        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        request_restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),grid_vip=config.grid_vip)
        sleep(20)
        
    @pytest.mark.run(order=2)
    def test_001_ospf_for_advertising_ipv4(self):
        ospf_ipv4_configuration()
                    
                    
    @pytest.mark.run(order=3)
    def test_002_anycast_ipv4_configuration(self):
        anycast_ipv4_configuration()

    @pytest.mark.run(order=4)
    def test_003_Anycast_restart_ON_behavior_ipv4(self):
        set_restart_anycast_on()


    @pytest.mark.run(order=5)
    def test_004_verifing_Anycast_restart_DNS_normally_ON_behavior_ipv4(self):
        print("\n====================================")    
        print("\nRestart DNS normally")
        print("\n====================================")
        changes_require_a_service_set_true()
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*","infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther"]
        flag_info=0
        flag_sys=0
       
        for look in LookFor_info:
            print(look)
            #logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1


        for look in LookFor_sys:
            print(look)
            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)

        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

        
               
        
    @pytest.mark.run(order=6)
    def test_005_verifing_Anycast_restart_DNS_ON_behavior_ipv4(self): 
        print("\n====================================")
        print("\nRestart DNS FORCE RESTART")
        print("\n====================================")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*","infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther"]
        flag_info=0
        flag_sys=0
        
        #LookFor_sys=".*infoblox.localdomain ospfd[.*].*notice Termi.*"
        flag_info=0
        flag_sys=0

        for look in LookFor_info:
            print(look)
            #logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1


        for look in LookFor_sys:
            print(look)
            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)

        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

        
          
    @pytest.mark.run(order=7)
    def test_006_Verifying_Anycast_stop_DNS_ON_behavior_ipv4(self):
        print("\n====================================")
        print("\nStop DNS services")
        print("\n====================================")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control.*Stopping zebra process.*"]
        
        
        LookFor_sys=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*notice exiting.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)  
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
            
          
    @pytest.mark.run(order=8)
    def test_007_Verifying_Anycast_start_DNS_ON_behavior_ipv4(self):
        print("\n====================================")
        print("\nStart DNS services")
        print("\n====================================")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)

        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info managed-keys-zone.*loaded serial.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting: vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

    # @pytest.mark.run(order=9)
    # def test_008_Verifying_Anycast_start_DNS_ON_behavior_ipv4_killall(self):
        # print("\n====================================")
        # print("\nKillall named process")
        # print("\n====================================")
        # log("start","/infoblox/var/infoblox.log",config.grid_vip)
        # log("start","/var/log/messages",config.grid_vip)
        
        # abnormally_kill_named()
        
        # log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        # log("stop","/var/log/messages",config.grid_vip)

        # LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*Stopping ospfd process.*",".*/infoblox/dns/bin/stop_dns_service).*Stopping zebra process.*",".*/infoblox/dns/bin/stop_dns_service).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]
        # flag_info=0
        # #flag_sys=0
        
        # for look in LookFor_info:
            # print(look)
            # logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            # print(logs)
            # if logs:
                # flag_info=flag_info+1
            
        # # for look in LookFor_sys:
            # # print(look)

            # # logs=logv(look,"/var/log/messages",config.grid_vip)
            # # print(logs)
            # # if logs:
                # # flag_sys=flag_sys+1
        # print(flag_info)   
        # if flag_info==len(LookFor_info):
            # assert True
        # else:
            # assert False
            
    @pytest.mark.run(order=9)
    def test_008_Anycast_stop_OFF_behavior_ipv4(self):
        set_restart_anycast_off()
        
 
    @pytest.mark.run(order=10)
    def test_009_verifing_Anycast_restart_DNS_normally_OFF_behavior_ipv4(self): 
        changes_require_a_service_set_false()
        print("\n====================================")
        print("\n Restart DNS services Normally")
        print("\n====================================")        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info_not=[".*infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*","infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther"]
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".* infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False              
                 
    @pytest.mark.run(order=11)
    def test_010_verifing_Anycast_restart_DNS_OFF_behavior_ipv4(self):
        print("\n====================================")
        print("\n Restart DNS services FORCE_RESTART")
        print("\n====================================")        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info_not=[".*infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*","infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther"]
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".* infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
            
    @pytest.mark.run(order=12)
    def test_011_install_bird_OFF_behavior_ipv4(self):

        install_bird_package("bird","10.36.198.8")

    @pytest.mark.run(order=13)
    def test_012_configure_bird_ipv4_OFF_behavior(self):
        #user_input=get_user_input("/home/test3/WAPI_PyTest/ib_utils/user_input.json")
        # child=pexpect.spawn("ssh root@"+config.grid_vip,  maxread=4000)
        # try:

            # child.expect("-bash-4.0#",timeout=100)
            # child.sendline("scp root@10.36.198.9:/usr/local/etc/bird.conf root@10.36.198.8:/root")
            # child.expect('password:',timeout=100)
            # child.sendline("infoblox")
            # child.expect("-bash-4.0#")
            # child.sendline("scp root@10.36.198.9:/usr/local/etc/arun.json root@10.36.198.8:/root/user_input.json")
            # child.expect('password:',timeout=100)
            # child.sendline("infoblox")
            # child.expect("-bash-4.0#")
            # child.sendline("exit")
            # print("\nSuccess: ")
            # child.close()
            # assert True

        # except Exception as e:
            # child.close()
            # print (e)
            # print("Failure: ")
            # assert False
            
        modify_bird_ipv4_conf_file_for_OSPF("user_input.json")

    @pytest.mark.run(order=14)
    def test_014_install_bird_OFF_behavior_ipv4(self):
        validate_the_uptime_during_restarts()

    @pytest.mark.run(order=15)
    def test_014_verifing_Anycast_stop_DNS_OFF_behavior_ipv4(self):      
        print("\n====================================")
        print("\n Stop DNS services")
        print("\n====================================")        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)


        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*now 2-Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: "+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*"]

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)           
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
       
    @pytest.mark.run(order=16)
    def test_015_verifing_Anycast_start_DNS_OFF_behavior_ipv4(self): 
        print("\n====================================")
        print("\n Stop DNS services")
        print("\n====================================")        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)


        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
                
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)               
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False   

    @pytest.mark.run(order=17)
    def test_016_Verifying_Anycast_start_DNS_OFF_behavior_ipv4_killall(self):
        print("\n====================================")
        print("\n Killall named process")
        print("\n====================================")        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        abnormally_kill_named()
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*info no longer listening.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
            
    @pytest.mark.run(order=18)
    def test_017_ospf_for_advertising_ipv6(self):
        ospf_for_advertising_ipv6()

    @pytest.mark.run(order=19)
    def test_018_anycast_ipv6_configuration(self):
        anycast_ipv6_configuration()
        
    @pytest.mark.run(order=20)
    def test_019_restart_anycast_ON_behavior_ipv6(self):
        set_restart_anycast_on()
        
    @pytest.mark.run(order=21)
    def test_020_verifing_Anycast_restart_DNS_normally_ON_behavior_ipv6(self): 
        print("\n====================================")
        print("\n Restart DNS services normally")
        print("\n====================================")
        changes_require_a_service_set_true()
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)
        
        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/dns/bin/named_control).*Process named.*stopped.*seconds elapsed.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys=[".*infoblox.localdomain ospf6d.*notice Terminating on signal SIGTERM.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux .*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain ospf6d.*notice OSPF6d.*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


    @pytest.mark.run(order=22)
    def test_021_verifing_Anycast_restart_DNS_ON_behavior_ipv6(self):
        print("\n====================================")
        print("\n Restart DNS service FORCE_RESTART")
        print("\n====================================")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/dns/bin/named_control).*Process named.*stopped.*seconds elapsed.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys=[".*infoblox.localdomain ospf6d.*notice Terminating on signal SIGTERM.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux .*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain ospf6d.*notice OSPF6d.*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

    @pytest.mark.run(order=23)
    def test_022_Verifying_Anycast_stop_DNS_ON_behavior_ipv6(self):
        print("\n====================================")
        print("\n Stop DNS service ")
        print("\n====================================")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*infoblox/one/bin/anycast_control).*Stopping zebra process.*"]
        
        
        LookFor_sys=[".*infoblox.localdomain ospf6d.*notice Terminating on signal SIGTERM.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)  
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
            
          
    @pytest.mark.run(order=24)
    def test_023_Verifying_Anycast_start_DNS_ON_behavior_ipv6(self):
        print("\n====================================")
        print("\n Start DNS service ")
        print("\n====================================")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)

        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice command channel listening on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain ospf6d.*notice OSPF6d.*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
        
    @pytest.mark.run(order=25)
    def test_024_stop_anycast_OFF_behavior_ipv6(self):
        set_restart_anycast_off()

    @pytest.mark.run(order=26)
    def test_025_verifing_Anycast_restart_DNS_normally_OFF_behavior_ipv6(self): 
    
        print("\n====================================")
        print("\n Restart DNS services normally")
        print("\n====================================")
        
        changes_require_a_service_set_false()
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info_not=[".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain ospf6d.*notice Terminating on signal SIGTERM.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain zebra.notice Zebra.*starting.*",".*infoblox.localdomain ospf6d.*notice OSPF6d.*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named info listening on IPv4 interface eth1, "+config.grid_vip+".*",".*infoblox.localdomain named.*notice fd.*receive buffer set to.*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)  
        
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
                 
    @pytest.mark.run(order=27)
    def test_026_verifing_Anycast_restart_DNS_OFF_behavior_ipv6(self):
        print("\n====================================")
        print("\n Restart DNS services FORCE_RESTART")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info_not=[".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain ospf6d.*notice Terminating on signal SIGTERM.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain zebra.notice Zebra.*starting.*",".*infoblox.localdomain ospf6d.*notice OSPF6d.*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on ::1.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named info listening on IPv4 interface eth1, "+config.grid_vip+".*",".*infoblox.localdomain named.*notice fd.*receive buffer set to.*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


            
         
    @pytest.mark.run(order=28)
    def test_027_verifing_Anycast_stop_DNS_OFF_behavior_ipv6(self): 
        
        print("\n====================================")
        print("\n Stop DNS services ")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        sleep(30)
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        
        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on ::1.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain ospf6d.*notice Terminating on signal SIGTERM.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*"]

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)                
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
       
    @pytest.mark.run(order=29)
    def test_028_verifing_Anycast_start_DNS_OFF_behavior_ipv6(self): 
        
        print("\n====================================")
        print("\n Start DNS services")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

       
        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain ospf6d.*notice OSPF6d.*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)           
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False   
            
            
            
    @pytest.mark.run(order=30)
    def test_029_bgp_for_advertising(self):          
        bgp_configuration()

    @pytest.mark.run(order=31)
    def test_030_anycast_ipv4_configuration(self):
        anycast_bgp_ipv4_configuration()
        
    @pytest.mark.run(order=32)
    def test_031_restart_anycast_ON_behavior_ipv4(self):
        set_restart_anycast_on()           

    @pytest.mark.run(order=33)
    def test_032_verifing_Anycast_restart_DNS_normally_ON_behavior_ipv4_BGP(self): 
        print("\n====================================")
        print("\n Restart DNS services normally")
        print("\n====================================")
        
        changes_require_a_service_set_true()
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)
        
        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo,.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo.*1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1, "+config.grid_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        flag_info=0
        flag_sys=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)

        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


    @pytest.mark.run(order=34)
    def test_033_verifing_Anycast_restart_DNS_ON_behavior_ipv4_BGP(self): 
        print("\n====================================")
        print("\n Restart DNS services FORCE_RESTART")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo,.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo.*1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1, "+config.grid_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        flag_info=0
        flag_sys=0

        flag_info=0
        flag_sys=0

        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)

        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

        
    @pytest.mark.run(order=35)
    def test_034_Verifying_Anycast_stop_DNS_ON_behavior_ipv4_BGP(self):
    
        print("\n====================================")
        print("\n Stop DNS services")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*topping zebra process.*"]
        
        
        LookFor_sys=[".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*notice exiting.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)  
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
            
          
    @pytest.mark.run(order=36)
    def test_035_Verifying_Anycast_start_DNS_ON_behavior_ipv4_BGP(self):
        print("\n====================================")
        print("\n Start DNS services ")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)

        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo.*",".*infoblox.localdomain named.*nfo listening on IPv4 interface lo:1, 1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1, "+config.grid_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*bgp.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
        
    @pytest.mark.run(order=37)
    def test_036_stop_anycast_OFF_behavior_ipv4_BGP(self):
        set_restart_anycast_off()
        

    @pytest.mark.run(order=38)
    def test_037_verifing_Anycast_restart_DNS_normally_OFF_behavior_ipv4_BGP(self): 
        print("\n====================================")
        print("\n Restart DNS services normally")
        print("\n====================================")
        
        changes_require_a_service_set_false()
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)
        
        LookFor_info_not=[".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]

        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1, "+config.grid_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        
 
        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


    @pytest.mark.run(order=39)
    def test_038_verifing_Anycast_restart_DNS_OFF_behavior_ipv4_BGP(self):
        print("\n====================================")
        print("\n Restart DNS services FORCE_RESTART")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info_not=[".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]

        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1, "+config.grid_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        
 
        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False



            
         
    @pytest.mark.run(order=40)
    def test_039_verifing_Anycast_stop_DNS_OFF_behavior_ipv4_BGP(self):
        print("\n====================================")
        print("\n Stop DNS services ")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

       
        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*"]

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys) 
        
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
       
    @pytest.mark.run(order=41)
    def test_040_verifing_Anycast_start_DNS_OFF_behavior_ipv4_BGP(self): 
        print("\n====================================")
        print("\n Start DNS services normally")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*bgp.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)               
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False   
    

    @pytest.mark.run(order=42)
    def test_041_anycast_ipv6_configuration_BGP(self):
        anycast_bgp_ipv6_configuration()
        
    @pytest.mark.run(order=43)
    def test_042_restart_anycast_ON_behavior_ipv6(self):
        set_restart_anycast_on()


    @pytest.mark.run(order=44)
    def test_043_verifing_Anycast_restart_DNS_normally_ON_behavior_ipv6_BGP(self): 
        print("\n====================================")
        print("\n Restart DNS services normally")
        print("\n====================================")
        
        changes_require_a_service_set_true()
        
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)
        
        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


        
    @pytest.mark.run(order=45)
    def test_044_verifing_Anycast_restart_DNS_ON_behavior_ipv6_BGP(self):
        print("\n====================================")
        print("\n Restart DNS services FORCE_RESTART")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


    @pytest.mark.run(order=46)
    def test_045_Verifying_Anycast_stop_DNS_ON_behavior_ipv6_BGP(self):
        print("\n====================================")
        print("\n Stop DNS services ")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*topping zebra process.*"]
        
        
        LookFor_sys=[".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)  
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
            
          
    @pytest.mark.run(order=47)
    def test_046_Verifying_Anycast_start_DNS_ON_behavior_ipv6_BGP(self):
        print("\n====================================")
        print("\n Start DNS services ")
        print("\n====================================")
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)

        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",
        ]

        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo.*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*bgp.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
        
    @pytest.mark.run(order=48)
    def test_047_stop_anycast_OFF_behavior_ipv6_BGP(self):
        set_restart_anycast_off()



    @pytest.mark.run(order=49)
    def test_048_verifing_Anycast_restart_DNS_normally_OFF_behavior_ipv6_BGP(self): 
        print("\n====================================")
        print("\n Restart DNS services normally")
        print("\n====================================")
        
        changes_require_a_service_set_false()
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)
        
        LookFor_info_not=[".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        

        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

            
    @pytest.mark.run(order=50)
    def test_049_verifing_Anycast_restart_DNS_OFF_behavior_ipv6_BGP(self):
        print("\n====================================")
        print("\n Restart DNS services FORCE_RESTART")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        
        LookFor_info_not=[".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        

        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

        
         
    @pytest.mark.run(order=51)
    def test_050_verifing_Anycast_stop_DNS_OFF_behavior_ipv6_BGP(self):   
        print("\n====================================")
        print("\n Stop DNS services ")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

       
        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*"]

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)                
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
       
    @pytest.mark.run(order=52)
    def test_051_verifing_Anycast_start_DNS_OFF_behavior_ipv6(self): 
        print("\n====================================")
        print("\n Start DNS services ")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",
        ".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*"]

        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo.*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*bgp.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)           
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False   
            
    @pytest.mark.run(order=53)
    def test_052_parental_and_subscriber_configuration_setup(self): 
        """
        setup method: Used for configuring pre-required configs.
        """
        
        '''Add DNS Resolver'''
        print("Add DNS Resolver 10.0.2.35")
        grid_ref = ib_NIOS.wapi_request('GET', object_type='grid')
        data = {"dns_resolver_setting":{"resolvers":["10.0.2.35"]}}
        response = ib_NIOS.wapi_request('PUT', ref=json.loads(grid_ref)[0]['_ref'], fields=json.dumps(data))
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Adding DNS Resolver")
                assert False

        '''Add DNS Forwarder'''
        print("Add DNS forwarder : 10.0.2.35")
        grid_dns_ref = ib_NIOS.wapi_request('GET', object_type='grid:dns')
        data = {"forwarders":["10.0.2.35"]}
        response = ib_NIOS.wapi_request('PUT', ref=json.loads(grid_dns_ref)[0]['_ref'], fields=json.dumps(data))
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Adding DNS Forwarder")
                assert False

 
        '''Enable logging for queries, responses, rpz'''
        print("Enable logging for queries, responses, rpz")
        data = {"logging_categories":{"log_queries":True, "log_responses":True, "log_rpz":True}}
        response = ib_NIOS.wapi_request('PUT', ref=json.loads(grid_dns_ref)[0]['_ref'], fields=json.dumps(data))
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Enabling logging for queries, responses, rpz")
                assert False
        
        print("Restart services")
        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']
        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices", fields=json.dumps(data))
        sleep(10)

        ''' Add Subscriber Site'''
        print("Add Subscriber Site")
        data={"name": "rfe_10176_subscbr",
              "maximum_subscribers": 1000000, 
              "members": [{"name": config.grid_fqdn}],
              "nas_gateways": [{"ip_address": "10.36.120.10","shared_secret": "test","name": "rfe_10176_nas","send_ack": True}]}
        subs_site = ib_NIOS.wapi_request('POST', object_type="parentalcontrol:subscribersite",fields=json.dumps(data))
        print(subs_site)
        if type(subs_site) == tuple:
            if subs_site[0]==400 or subs_site[0]==401:
                print("Failure: Adding subscriber site")
                assert False

        print("Restart services")
        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']
        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices", fields=json.dumps(data))
        sleep(10)

        ''' Enable Parental Control'''
        print("Enable Parental Control")
        get_ref = ib_NIOS.wapi_request('GET', object_type="parentalcontrol:subscriber")
        print(get_ref)
        data={"enable_parental_control": True,
              "cat_acctname":"InfoBlox", 
              "cat_password":"CSg@vBz!rx7A",
              "category_url":"https://pitchers.rulespace.com/ufsupdate/web.pl",
              "proxy_url":"http://10.196.9.113:8001", 
              "proxy_username":"client", 
              "proxy_password":"infoblox",
              "pc_zone_name":"rfe_10176.zone.com", 
              "ident":"pkFu-yhrf-qPOV-s5BU",
              "cat_update_frequency":24}
        response = ib_NIOS.wapi_request('PUT', ref=json.loads(get_ref)[0]["_ref"],fields=json.dumps(data))
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Enabling parental control")
                assert False
        sleep(30)

        print("Restart services")
        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']
        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices", fields=json.dumps(data))
        sleep(10)


         
        '''Start Subscriber Collection Service on the Master'''
        print("Start Subscriber Collection Service")
        get_ref = ib_NIOS.wapi_request('GET', object_type="member:parentalcontrol")
        print(get_ref)
        data= {"enable_service": True}
        response = ib_NIOS.wapi_request('PUT', ref=json.loads(get_ref)[0]["_ref"],fields=json.dumps(data))
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Starting subscriber Collection Service")
                assert False
                
        print("Restart services")
        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']
        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices", fields=json.dumps(data))
        sleep(20)

    @pytest.mark.run(order=54)
    def test_053_change_anycast_behaviour_in_interim_state_scenario_1(self):
    
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        set_restart_anycast_on()
        
        subscriber_start_services()
        
        dns_start_services()
        
        #check_process_response_when_SS_ON()
        
        set_restart_anycast_off()
        
        subscriber_stop_services()
        
        
        dns_start_services()
        
        check_process_response_id_when_SS_ON()
        
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        
        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*set restart_anycast_with_dns_restart off.*",".*/infoblox/one/bin/monitor) snmp_trap.c:1491 one_send_snmp_trap(): Sending state change trap for.*"+config.grid_vip+".*imc_servers (Subscriber Collection Service is inactive) from 138 to 136.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]
        
        LookFor_sys=[".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info nsm_change_state.*scheduling new router-LSA origination.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*1.3.3.3 now Down.*",".*infoblox.localdomain ospf6d.*notice Terminating on signal SIGTERM.*",".*infoblox.localdomain zebra.*notice client 18 disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*, bgp.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d.*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*",".*infoblox.localdomain ospfd.*warning interface eth1.*"+config.grid_vip+".*ospf_read invalid Area ID 0.0.0.2.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*"+config.grid_vip+".*now Init/DROther.*",".*infoblox.localdomain ospfd.*info Packet[DD].*Neighbor.*"+config.grid_vip+".*Negotiation done (Master).*",".*infoblox.localdomain ospfd.*info nsm_change_state.*scheduling new router-LSA origination.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)           
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False   
        
    @pytest.mark.run(order=55)
    def test_054_change_anycast_behaviour_in_interim_state_scenario_2(self):
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        set_restart_anycast_off()
        
   
        subscriber_start_services()
        
        dns_start_services()
        
        check_process_response_when_SS_ON()
        
        set_restart_anycast_on()   
     
        subscriber_stop_services()

        
        dns_restart_services()
        check_process_response_id_when_SS_ON()
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        
        LookFor_info=[".*/infoblox/one/bin/monitor) monitor.c.*ib_monitor_set_monitor_data().*Type.*IMC, State.*Yellow, Event.*Initial Subscriber Collection service interim Interval state change from 136 to 138.*",".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*set restart_anycast_with_dns_restart on.*",".*/infoblox/one/bin/monitor) snmp_trap.c.*one_send_snmp_trap().*Sending state change trap for.*"+config.grid_vip+".*imc_servers (Subscriber Collection Service is inactive) from 138 to 136.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]
        
        LookFor_sys=[".*infoblox.localdomain monitor.*err Type.*IMC, State.*Yellow, Event.*Initial Subscriber Collection service interim Interval state change from 136 to 138.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info nsm_change_state.*scheduling new router-LSA origination.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospf6d.*notice Terminating on signal SIGTERM.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain named.*info received control channel command.*ib-subscriber-cache clear.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 10.36.152.8 now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d.*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)           
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False         

    @pytest.mark.run(order=56)
    def test_055_change_anycast_behaviour_from_interim_state_scenario_3(self):
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        set_restart_anycast_on()
        
   
        subscriber_start_services()
        
        dns_start_services()
        
        check_process_response_when_SS_ON()
  
     
        subscriber_stop_services()
        
        dns_restart_services()
        check_process_response_id_when_SS_ON()
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        
        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/monitor) snmp_trap.c:1491 one_send_snmp_trap(): Sending state change trap for.*"+config.ipv6_vip+".*imc_servers (Subscriber Collection Service is inactive) from 138 to 136.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]
        
        LookFor_sys=[".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info nsm_change_state.*scheduling new router-LSA origination.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*1.3.3.3 now Down.*",".*infoblox.localdomain ospf6d.*notice Terminating on signal SIGTERM.*",".*infoblox.localdomain zebra.*notice client 18 disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*, bgp.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d.*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*",".*infoblox.localdomain ospfd.*warning interface eth1.*"+config.grid_vip+".*ospf_read invalid Area ID 0.0.0.2.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*"+config.grid2_vip+".*now Init/DROther.*",".*infoblox.localdomain ospfd.*info Packet[DD].*Neighbor.*"+config.grid2_vip+".*Negotiation done (Master).*",".*infoblox.localdomain ospfd.*info nsm_change_state.*scheduling new router-LSA origination.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)           
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False  
            
    @pytest.mark.run(order=57)
    def test_056_change_anycast_behaviour_from_interim_state_scenario_4(self):
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        set_restart_anycast_off()
        
   
        subscriber_start_services()
        
        dns_start_services()
        
        check_process_response_when_SS_ON()
        
            
        subscriber_stop_services()
        
        dns_restart_services()
        
        check_process_response_when_SS_ON()
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        
        LookFor_info=[".*/infoblox/one/bin/monitor) monitor.c.*ib_monitor_set_monitor_data().*Type.*IMC, State.*Yellow, Event.*Initial Subscriber Collection service interim Interval state change from 136 to 138.*",".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*set restart_anycast_with_dns_restart on.*",".*/infoblox/one/bin/monitor) snmp_trap.c.*one_send_snmp_trap().*Sending state change trap for.*"+config.grid_vip+".*imc_servers (Subscriber Collection Service is inactive) from 138 to 136.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]
        
        LookFor_sys=[".*infoblox.localdomain monitor.*err Type.*IMC, State.*Yellow, Event.*Initial Subscriber Collection service interim Interval state change from 136 to 138.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info nsm_change_state.*scheduling new router-LSA origination.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospf6d.*notice Terminating on signal SIGTERM.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain named.*info received control channel command.*ib-subscriber-cache clear.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d.*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)           
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False        
            

    @pytest.mark.run(order=58)
    def test_057_setting_intrim_time_to_make_SS_ruuning(self):
    
        print("Setting intrim time")
        get_ref = ib_NIOS.wapi_request('GET', object_type="parentalcontrol:subscriber")
        print(get_ref)
        data={"interim_accounting_interval":2}
        response = ib_NIOS.wapi_request('PUT', ref=json.loads(get_ref)[0]["_ref"],fields=json.dumps(data))
        print(response)
        if type(response) == tuple:
            if response[0]==400 or response[0]==401:
                print("Failure: Setting intrim time")
                assert False
        
        print("Restart services")
        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']
        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices", fields=json.dumps(data))
        sleep(10)

        changes_require_a_service_set_true()
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        
        subscriber_start_services()
        
        sleep(60)
        print("Restart services")
        grid =  ib_NIOS.wapi_request('GET', object_type="grid")
        ref = json.loads(grid)[0]['_ref']
        data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices", fields=json.dumps(data))
        sleep(10)
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
       
        look="Sending state change trap for.*"+config.grid_vip+".*imc_servers (Subscriber Collection Service is working) from 138 to 133"
        logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
        print(logs)
        if logs:
            print("Subscriber is working.......!")
            assert True
        else:
            print("Subscriber is NOT working.......!")
            assert False
        
    @pytest.mark.run(order=59)
    def test_058_verifing_Anycast_restart_DNS_normally_ON_behavior_both_ipv4_ipv6(self): 
        set_restart_anycast_on()
        
        sleep(30)
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        check_process_response_id_when_SS_ON()
        dns_restart_services_normally()
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)
        
        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys=[".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d .*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==1 and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


    @pytest.mark.run(order=60)
    def test_059_verifing_Anycast_restart_DNS_ON_behavior_both_ipv4_ipv6(self):

        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys=[".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d .*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==1 and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

    @pytest.mark.run(order=61)
    def test_060_Verifying_Anycast_stop_DNS_ON_behavior_both_ipv4_ipv6(self):
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*"]
        
        
        LookFor_sys=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*notice exiting.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)  
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
            
          
    @pytest.mark.run(order=62)
    def test_061_Verifying_Anycast_start_DNS_ON_behavior_both_ipv4_ipv6(self):

        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)

        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo.*1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info listening on IPv6 interface lo.*3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra[.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*bgp.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
        
       

    @pytest.mark.run(order=63)
    def test_062_verifing_Anycast_restart_DNS_normally_OFF_behavior_both_ipv4_ipv6(self): 
        
        set_restart_anycast_off()
        
        changes_require_a_service_set_false()
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info_not=[".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d .*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        
        
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1, "+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]

        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
                 
    @pytest.mark.run(order=64)
    def test_063_verifing_Anycast_restart_DNS_OFF_behavior_both_ipv4_ipv6(self):
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info_not=[".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d .*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        
        
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1, "+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]


        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


            
         
    @pytest.mark.run(order=65)
    def test_064_verifing_Anycast_stop_DNS_OFF_behavior_both_ipv4_ipv6(self):       
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        
        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*"]

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)                
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
       
    @pytest.mark.run(order=66)
    def test_065_verifing_Anycast_start_DNS_OFF_behavior_both_ipv4_ipv6(self): 
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

       
        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*bgp.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)           
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False   
            
            
    @pytest.mark.run(order=67)
    def test_066_HA_pair_failover(self):   
        set_restart_anycast_on()
        flag_bgp=True
        flag_osfp=True
        flag_zebra=True
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.192.6", username='root', pkey = mykey)
        data="pgrep ospf\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(len(stdout))
        
        if len(stdout)==0:
            flag_bgp=False
            client.close()

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.192.6", username='root', pkey = mykey)
        data="pgrep bgp\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(len(stdout))
            
        if len(stdout)==0:
            flag_osfp=False
            client.close() 
            
            
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.192.6", username='root', pkey = mykey)
        data="pgrep zebra\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(len(stdout))        
        if len(stdout)==0:
            flag_zebra=False
            client.close()   
            
        if flag_bgp==True and flag_osfp==True and flag_zebra==True:
            assert True
        else:
            assert False
            
            
        reboot()
        
        
        flag_bgp=False
        flag_osfp=False
        flag_zebra=False
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.144.8", username='root', pkey = mykey)
        data="pgrep bgp\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(len(stdout))
        
        if len(stdout)==0:
            flag_bgp=True
            client.close()
            
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.144.8", username='root', pkey = mykey)
        data="pgrep ospf\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(stdout)
        
        if len(stdout)==0:
            flag_osfp=True
            client.close()   

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.144.8", username='root', pkey = mykey)
        data="pgrep zebra\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(stdout)
        
        if len(stdout)==0:
            flag_zebra=True
            client.close()   
            
        if flag_bgp==True and flag_osfp==True and flag_zebra==True:
            assert True
        else:
            assert False

        

    @pytest.mark.run(order=68)
    def test_067_verifing_Anycast_restart_DNS_normally_ON_behavior_HA(self): 
    
        changes_require_a_service_set_true()
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*","infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther"]
        flag_info=0
        flag_sys=0
        
        #LookFor_sys=".*infoblox.localdomain ospfd[.*].*notice Termi.*"
        flag_info=0
        flag_sys=0

    
        #logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
        logs=logv(LookFor_info,"/infoblox/var/infoblox.log",config.grid_vip)
        print(logs)
        if logs:
            flag_info=flag_info+1



        logs=logv(LookFor_sys,"/var/log/messages",config.grid_vip)
        print(logs)
        if logs:
            flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)

        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
               
        
    @pytest.mark.run(order=69)
    def test_068_verifing_Anycast_restart_DNS_ON_behavior_HA(self): 
       
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*","infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther"]
        flag_info=0
        flag_sys=0
        
        #LookFor_sys=".*infoblox.localdomain ospfd[.*].*notice Termi.*"
        flag_info=0
        flag_sys=0

        for look in LookFor_info:
            print(look)
            #logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1


        for look in LookFor_sys:
            print(look)
            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)

        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

        
          
    @pytest.mark.run(order=70)
    def test_069_Verifying_Anycast_stop_DNS_ON_behavior_HA(self):
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control.*Stopping zebra process.*"]
        
        
        LookFor_sys=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*notice exiting.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)  
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
            
          
    @pytest.mark.run(order=71)
    def test_070_Verifying_Anycast_start_DNS_ON_behavior_HA(self):

        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)

        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]

        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info managed-keys-zone.*loaded serial.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting: vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
            
            
    @pytest.mark.run(order=72)
    def test_071_setting_restart_anycast_off_HA(self):
        print("setting restart_anycast_with_dns_restart off")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@10.35.192.6')
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set restart_anycast_with_dns_restart off')
            child.expect('ERROR: This setting may only be changed on the active MASTER')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: ")
            print (e)
            assert False
  

    @pytest.mark.run(order=73)
    def test_072_HA_pair_failover(self): 
        
        set_restart_anycast_off()
        #reboot()
        flag_bgp=True
        flag_osfp=True
        flag_zebra=True
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.192.6", username='root', pkey = mykey)
        data="pgrep ospf\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(len(stdout))
        
        if len(stdout)==0:
            flag_bgp=False
            client.close()

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.192.6", username='root', pkey = mykey)
        data="pgrep bgp\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(len(stdout))
            
        if len(stdout)==0:
            flag_osfp=False
            client.close() 
            
            
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.192.6", username='root', pkey = mykey)
        data="pgrep zebra\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(len(stdout))        
        if len(stdout)==0:
            flag_zebra=False
            client.close()   
            
        if flag_bgp==True and flag_osfp==True and flag_zebra==True:
            assert True
        else:
            assert False
            
            
        reboot()
        
        
        flag_bgp=False
        flag_osfp=False
        flag_zebra=False
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.144.8", username='root', pkey = mykey)
        data="pgrep bgp\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(len(stdout))
        
        if len(stdout)==0:
            flag_bgp=True
            client.close()
            
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.144.8", username='root', pkey = mykey)
        data="pgrep ospf\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(stdout)
        
        if len(stdout)==0:
            flag_osfp=True
            client.close()   

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekeyfile = os.path.expanduser('~/.ssh/id_rsa')
        mykey = paramiko.RSAKey.from_private_key_file(privatekeyfile)
        client.connect("10.35.144.8", username='root', pkey = mykey)
        data="pgrep zebra\n"
        stdin, stdout, stderr = client.exec_command(data)
        stdout=stdout.read()
        print(stdout)
        
        if len(stdout)==0:
            flag_zebra=True
            client.close()   
            
        if flag_bgp==True and flag_osfp==True and flag_zebra==True:
            assert True
        else:
            assert False

        changes_require_a_service_set_false()

    @pytest.mark.run(order=74)
    def test_073_verifing_Anycast_restart_DNS_normally_OFF_behavior_HA(self): 
        
        changes_require_a_service_set_false()
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info_not=[".*infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*","infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther"]
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".* infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


               
                 
    @pytest.mark.run(order=75)
    def test_074_verifing_Anycast_restart_DNS_OFF_behavior_HA(self):
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info_not=[".*infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*","infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther"]
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".* infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        flag_info_not=1
        flag_sys_not=1
        
        for look in LookFor_info_not:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info_not=0
            
        for look in LookFor_sys_not:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys_not=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info_not,flag_sys_not,flag_info,flag_sys)                
        if flag_info_not==1 and flag_sys_not==1 and flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

    @pytest.mark.run(order=76)
    def test_075_verifing_Anycast_stop_DNS_OFF_behavior_HA(self):       
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)


        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on "+config.grid_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapNbrStateChange trap sent.*now 2-Way/DROther.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: "+config.grid_vip+" now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*"]

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)           
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
       
    @pytest.mark.run(order=77)
    def test_076_verifing_Anycast_start_DNS_OFF_behavior_HA(self): 
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)


        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on.*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*vty@2601.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*vty@2604.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+" now DROther.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
                
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)               
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False   
            
    @pytest.mark.run(order=78)
    def test_077_GMC_grid_master_condidate_ON_behaviour(self):   
        print("setting restart_anycast_with_dns_restart on")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_member1_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set restart_anycast_with_dns_restart on')
            child.expect('ERROR: This setting may only be changed on the active MASTER')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Con't perform restart anycast on")
            print (e)
            assert False
            
            
    @pytest.mark.run(order=79)
    def test_078_GMC_grid_master_condidate_OFF_behaviour(self):
        print("setting restart_anycast_with_dns_restart off")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_member1_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set restart_anycast_with_dns_restart off')
            child.expect('ERROR: This setting may only be changed on the active MASTER')
            child.expect('>')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Con't perform restart anycast off")
            print (e)
            assert False 

 
    @pytest.mark.run(order=80)
    def test_079_GMC_promote_HA_as_master_candidate(self):
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_member1_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set promote_master')
            child.expect('y or n')
            child.sendline('y')
            child.expect('y or n')
            child.sendline('y')
            sleep(60)
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Can't GMC promote HA as master candidate")
            print (e)
            assert False
            
            
    @pytest.mark.run(order=81)
    def test_080_GMC_promoted_master_candidate_ON_behaviour(self):
        print("setting restart_anycast_with_dns_restart on")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_member1_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set restart_anycast_with_dns_restart on')
            child.expect('>')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Con't perform restart anycast on")
            print (e)
            assert False
            
    @pytest.mark.run(order=82)
    def test_081_GMC_promoted_master_candidate_OFF_behaviour(self):
        print("setting restart_anycast_with_dns_restart off")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_member1_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set restart_anycast_with_dns_restart off')
            child.expect('>')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Con't perform restart anycast off")
            print (e)
            assert False

    @pytest.mark.run(order=83)
    def test_082_execute_cli_Maintainance_expert_fips_cc_modes_ON_behavior(self):
        print("setting restart_anycast_with_dns_restart ON")
        
        print("--------------Maintainance mode-----------------")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set maintenancemode')
            child.expect('Maintenance Mode >')
            child.sendline('set restart_anycast_with_dns_restart on')
            child.expect('Maintenance Mode >')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Can't perform Maintenance mode")
            print (e)
            assert False
            
            
        print("--------------CC mode-----------------")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set cc_mode')
            child.expect('Enable Common Criteria mode? (y or n):')
            child.sendline('y')
            child.expect('is this correct? (y or n):')
            child.sendline('y')
            child.expect('Are you sure you want to continue (y or n): y')
            child.sendline('y')
            sleep(60)
            child.expect('login:')
            child.sendline('admin')
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('show cc_mode')
            child.expect('Common Criteria Mode Enabled:  Yes')
            child.sendline('set restart_anycast_with_dns_restart on')
            child.expect('>')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Can't perform cc mode")
            print (e)
            assert False
       
                    
        print("--------------FIPS mode-----------------")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set fips_mode')
            child.expect('y or n')
            child.sendline('y')
            child.expect('y or n')
            child.sendline('y')
            child.expect('y or n')
            child.sendline('y')
            sleep(900)
            child.expect('login:')
            child.sendline('admin')
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set restart_anycast_with_dns_restart on')
            child.expect('>')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Can't perform FIFS mode")
            print (e)
            assert False
        
        
    @pytest.mark.run(order=84)
    def test_083_execute_cli_Maintainance_expert_fips_cc_modes_OFF_behavior(self):
        print("setting restart_anycast_with_dns_restart OFF")
        
        print("--------------Maintainance mode-----------------")
        
        
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set maintenancemode')
            child.expect('Maintenance Mode >')
            child.sendline('set restart_anycast_with_dns_restart off')
            child.expect('Maintenance Mode >')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Can't perform Maintenance mode")
            print (e)
            assert False

        print("--------------CC mode-----------------")
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set cc_mode')
            child.expect('Enable Common Criteria mode? (y or n):')
            child.sendline('y')
            child.expect('is this correct? (y or n):')
            child.sendline('y')
            child.expect('Are you sure you want to continue (y or n): y')
            child.sendline('y')
            sleep(60)
            child.expect('login:')
            child.sendline('admin')
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('show cc_mode')
            child.expect('Common Criteria Mode Enabled:  Yes')
            child.sendline('set restart_anycast_with_dns_restart off')
            child.expect('>')
            child.close() 
            assert True
                       
        except Exception as e:
            child.close()
            print("Failure: Can't perform CC mode")
            print (e)
            assert False
            
        print("--------------FIPS mode-----------------")
        
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set fips_mode')
            child.expect('Enable FIPS mode? (y or n):')
            child.sendline('y')
            child.expect('is this correct? (y or n):')
            child.sendline('y')
            child.expect('Are you sure you want to continue (y or n):')
            child.sendline('y')
            sleep(60)
            child.expect('login:')
            child.sendline('admin')
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set restart_anycast_with_dns_restart off')
            child.expect('Infoblox >')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Can't perform FIFS mode")
            print (e)
            assert False
            
            
            
    @pytest.mark.run(order=85)
    def test_084_audit_log_should_contain_the_log_ON_behavior(self):
        print("\n====================================")
        print("\n Checking Audit in ON behavior")
        print("\n====================================")
        
        log("start","/infoblox/var/audit.log",config.grid_vip)
        set_restart_anycast_on()
        
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        LookFor_audit=[".*admin.*Called.*set_restart_anycast_with_dns_restart.*enable_anycast_restart.*true from false.*"]
        flag_audit=0
        
        for look in LookFor_audit:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_audit=flag_audit+1
        
        
        print(flag_audit)               
        if flag_audit==len(LookFor_audit):
            assert True
        else:
            assert False  

    @pytest.mark.run(order=86)
    def test_085_audit_log_should_contain_the_log_OFF_behavior(self):
        print("\n====================================")
        print("\n Checking Audit in OFF behavior")
        print("\n====================================")
        
        log("start","/infoblox/var/audit.log",config.grid_vip)
        set_restart_anycast_off()
        
        log("stop","/infoblox/var/audit.log",config.grid_vip)
        
        LookFor_audit=[".*admin.*Called.*set_restart_anycast_with_dns_restart.*enable_anycast_restart.*false from true.*"]
        flag_audit=0
        
        for look in LookFor_audit:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_audit=flag_audit+1
        
        
        print(flag_audit)               
        if flag_audit==len(LookFor_audit):
            assert True
        else:
            assert False 
  
    @pytest.mark.run(order=87)
    def test_086_Execute_cli_for_member(self):
    
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_member1_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set restart_anycast_with_dns_restart on')
            child.expect('>')
            child.sendline('set restart_anycast_with_dns_restart off')
            child.expect('>')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Can't perform restart anycast on/off")
            print (e)
            assert False
  

    @pytest.mark.run(order=88)
    def test_087_restart_without_anycast_config_ON_behavior(self):
        set_restart_anycast_on()           

    @pytest.mark.run(order=89)
    def test_088_verifing_without_Anycast_config_restart_DNS_normally_ON_behavior(self): 
        print("\n====================================")
        print("\n Restart DNS services normally")
        print("\n====================================")
        
        changes_require_a_service_set_true()
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)
        
        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys=[".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d .*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        flag_info=0
        flag_sys=0

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)

        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


    @pytest.mark.run(order=90)
    def test_089_verifing_without_Anycast_config_restart_DNS_ON_behavior(self): 
        print("\n====================================")
        print("\n Restart DNS services FORCE_RESTART")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys=[".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info listening on IPv6 interface lo, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf routes",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d .*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        flag_info=0
        flag_sys=0

        flag_info=0
        flag_sys=0

        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)

        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False

        
    @pytest.mark.run(order=91)
    def test_090_Verifying_without_Anycast_config_stop_DNS_ON_behavior(self):
    
        print("\n====================================")
        print("\n Stop DNS services")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*"]
        
        
        LookFor_sys=[".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*1.3.3.3 now Down.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf6 routes removed from the rib.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*info no longer listening on 1.3.3.3.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*notice exiting.*"]
        
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)  
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
            
          
    @pytest.mark.run(order=92)
    def test_091_Verifying_without_Anycast_config_start_DNS_ON_behavior(self):
        print("\n====================================")
        print("\n Start DNS services ")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)

        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo.*1.3.3.3.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1.*"+config.grid_vip+".*",".*infoblox.localdomain named.*info listening on IPv6 interface lo.*3333::3331.*",".*infoblox.localdomain named.*info listening on IPv6 interface eth1.*"+config.grid2_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra[.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*bgp.*",".*infoblox.localdomain ospfd.*notice OSPFd.*starting.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*"]
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)   
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
        
    @pytest.mark.run(order=93)
    def test_092_stop_without_anycast_config_OFF_behavior_zone(self):
        set_restart_anycast_off()
        

    @pytest.mark.run(order=94)
    def test_093_verifing_without_anycast_config_restart_DNS_normally_OFF_behavior(self): 
        print("\n====================================")
        print("\n Restart DNS services normally")
        print("\n====================================")
        
        changes_require_a_service_set_false()
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services_normally()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)
        
        LookFor_info_not=[".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d .*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        
        
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1, "+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        
 
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)                
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


    @pytest.mark.run(order=95)
    def test_094_verifing_without_anycast_config_restart_DNS_OFF_behavior(self):
        print("\n====================================")
        print("\n Restart DNS services FORCE_RESTART")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_restart_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info_not=[".*/infoblox/one/bin/anycast_control).*Stopping ospfd process.*",".*/infoblox/one/bin/anycast_control).*Stopping ospf6d process.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/firewall).*Disabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*",".*/infoblox/one/bin/firewall).*Enabled firewall BGP.*",".*/infoblox/one/bin/anycast_control).*Starting ospfd process.*",".*/infoblox/one/bin/anycast_control).*Starting ospf6d process.*"]

        
        LookFor_sys_not=[".*infoblox.localdomain zebra.*notice client.*disconnected.*ospf routes removed from the rib.*",".*infoblox.localdomain ospfd.*notice Terminating on signal.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent: 1.3.3.3 now Down.*",".*infoblox.localdomain ospfd.*info ospfTrapIfStateChange trap sent.*"+config.grid_vip+".*now DROther.*",".*infoblox.localdomain ospf6d.*notice OSPF6d .*starts.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only ospf6 routes.*"]
        
        
        
        LookFor_info=[".*/infoblox/dns/bin/named_control).*Sending SIGTERM to named process.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command channel on.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1, "+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*"]
        
 
        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys)                
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False


            
         
    @pytest.mark.run(order=96)
    def test_095_verifing_without_anycast_config_stop_DNS_OFF_behavior(self):
        print("\n====================================")
        print("\n Stop DNS services ")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_stop_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

       
        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping bgpd process.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*info shutting down.*",".*infoblox.localdomain named.*notice stopping command.*",".*infoblox.localdomain named.*info no longer listening on.*",".*infoblox.localdomain named.*info no longer listening on 3333::3331.*",".*infoblox.localdomain named.*info no longer listening on "+config.ipv6_vip+".*",".*infoblox.localdomain named.*notice exiting.*",".*infoblox.localdomain bgpd.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*notice client.*disconnected.*bgp routes removed from the rib.*",".*infoblox.localdomain zebra.*notice Terminating on signal.*",".*infoblox.localdomain zebra.*info IRDP.*Received shutdown notification.*"]

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
                
        print(flag_info,flag_sys) 
        
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False
       
    @pytest.mark.run(order=97)
    def test_096_verifing_without_anycast_config_start_DNS_OFF_behavior(self): 
        print("\n====================================")
        print("\n Start DNS services normally")
        print("\n====================================")
        
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        log("start","/var/log/messages",config.grid_vip)
        
        dns_start_services()
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/stop_dns_service).*stopping named services.*",".*/infoblox/one/bin/anycast_control).*Stopping zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting zebra process.*",".*/infoblox/one/bin/anycast_control).*Starting bgpd process.*"]
        
        LookFor_sys=[".*infoblox.localdomain named.*notice starting BIND.*(Supported Preview Version).*",".*infoblox.localdomain named.*notice running on Linux.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo.*",".*infoblox.localdomain named.*info listening on IPv4 interface lo:1, 3333::3331.*",".*infoblox.localdomain named.*info listening on IPv4 interface eth1.*"+config.ipv6_vip+".*",".*infoblox.localdomain named.*info all zones loaded.*",".*infoblox.localdomain named.*notice running.*",".*infoblox.localdomain zebra.*notice Zebra.*starting.*",".*infoblox.localdomain bgpd.*notice BGPd.*starting.*bgp.*",".*infoblox.localdomain zebra.*notice client.*says hello and bids fair to announce only bgp routes.*"]
        

        flag_info=0
        flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        for look in LookFor_sys:
            print(look)

            logs=logv(look,"/var/log/messages",config.grid_vip)
            print(logs)
            if logs:
                flag_sys=flag_sys+1
        print(flag_info,flag_sys)               
        if flag_info==len(LookFor_info) and flag_sys==len(LookFor_sys):
            assert True
        else:
            assert False   
    
    
    