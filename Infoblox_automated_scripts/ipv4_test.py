#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Shashikala R S"
__email__  = "srs@infoblox.com"

#############################################################################
# Grid Set up required:                                                     #
#  1. Licenses : Grid,DNS,RPZ license                                                  #
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

logging.basicConfig(format='%(asctime)s - %(name)s(%(process)d) - %(levelname)s - %(message)s',filename=".log" ,level=logging.DEBUG,filemode='w')

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
    sleep(90)
    
    
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
    data="killall named\n"
    stdin, stdout, stderr = client.exec_command(data)
    stdout=stdout.read()
    print(stdout)
    sleep(15)


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
        
    if flag_bgp==True and flag_osfp==True and flag_zebra==True:
    
        assert True
    else:
        assert False
/infoblox/one/bin/monitor) snmp_trap.c:1491 one_send_snmp_trap(): Sending state change trap for 10.36.152.8 - imc_servers (Subscriber Collection Service is inactive) from 138 to 136
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
    
    # @pytest.mark.run(order=1)
    # def test_000_create_New_AuthZone(self):
        # dns_start_services()
        # for i in range(1000):
            # data = {"fqdn": "zone"+str(i)+".com","grid_primary": [{"name": config.grid_member_fqdn,"stealth":False}]}
            # response = ib_NIOS.wapi_request('POST', object_type="zone_auth", fields=json.dumps(data))
            # print(response)
            
            # if type(response) == tuple:
                # if response[0]==400 or response[0]==401 or response[0]==401:
                    # print("Failure: Create A new Zone")
                    # assert False
                # else:
                    # print("Success: Create A new Zone")
                    # assert True
         
        # print("Restart DHCP Services")
        # grid =  ib_NIOS.wapi_request('GET', object_type="grid", grid_vip=config.grid_vip)
        # ref = json.loads(grid)[0]['_ref']
        # data= {"member_order" : "SIMULTANEOUSLY","restart_option":"FORCE_RESTART","service_option": "ALL"}
        # request_restart = ib_NIOS.wapi_request('POST', object_type = ref + "?_function=restartservices",fields=json.dumps(data),grid_vip=config.grid_vip)
        # sleep(20)
        
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
    def test_004_changes_require_a_service_restart_ON_behaviour(self):
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

    @pytest.mark.run(order=6)
    def test_005_verifing_Anycast_restart_DNS_normally_ON_behavior_ipv4(self): 
       
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
               
        
    @pytest.mark.run(order=7)
    def test_006_verifing_Anycast_restart_DNS_ON_behavior_ipv4(self): 
       
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

        
          
    @pytest.mark.run(order=8)
    def test_007_Verifying_Anycast_stop_DNS_ON_behavior_ipv4(self):
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
            
          
    @pytest.mark.run(order=9)
    def test_008_Verifying_Anycast_start_DNS_ON_behavior_ipv4(self):

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

    @pytest.mark.run(order=10)
    def test_009_Verifying_Anycast_start_DNS_ON_behavior_ipv4_killall(self):
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        #log("start","/var/log/messages",config.grid_vip)
        
        abnormally_kill_named()
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        #log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/dns/bin/named_control.*"]
        flag_info=0
        #flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        # for look in LookFor_sys:
            # print(look)

            # logs=logv(look,"/var/log/messages",config.grid_vip)
            # print(logs)
            # if logs:
                # flag_sys=flag_sys+1
        print(flag_info)   
        if flag_info==len(LookFor_info):
            assert True
        else:
            assert False
            
    @pytest.mark.run(order=11)
    def test_010_Anycast_stop_OFF_behavior_ipv4(self):
        set_restart_anycast_off()
        
    @pytest.mark.run(order=12)
    def test_011_changes_require_a_service_restart_OFF_behaviour(self):
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

    @pytest.mark.run(order=13)
    def test_012_verifing_Anycast_restart_DNS_normally_OFF_behavior_ipv4(self): 
       
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


               
                 
    @pytest.mark.run(order=14)
    def test_013_verifing_Anycast_restart_DNS_OFF_behavior_ipv4(self):
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
            
    # @pytest.mark.run(order=15)
    # def test_014_install_bird_OFF_behavior_ipv4(self):

        # install_bird_package("bird","10.36.198.8")

    # @pytest.mark.run(order=16)
    # def test_015_configure_bird_ipv4_OFF_behavior(self):
        # #user_input=get_user_input("/home/test3/WAPI_PyTest/ib_utils/user_input.json")
        # # child=pexpect.spawn("ssh root@"+config.grid_vip,  maxread=4000)
        # # try:

            # # child.expect("-bash-4.0#",timeout=100)
            # # child.sendline("scp root@10.36.198.9:/usr/local/etc/bird.conf root@10.36.198.8:/root")
            # # child.expect('password:',timeout=100)
            # # child.sendline("infoblox")
            # # child.expect("-bash-4.0#")
            # # child.sendline("scp root@10.36.198.9:/usr/local/etc/arun.json root@10.36.198.8:/root/user_input.json")
            # # child.expect('password:',timeout=100)
            # # child.sendline("infoblox")
            # # child.expect("-bash-4.0#")
            # # child.sendline("exit")
            # # print("\nSuccess: ")
            # # child.close()
            # # assert True

        # # except Exception as e:
            # # child.close()
            # # print (e)
            # # print("Failure: ")
            # # assert False
            
        # modify_bird_ipv4_conf_file_for_OSPF("user_input.json")

    # @pytest.mark.run(order=17)
    # def test_016_install_bird_OFF_behavior_ipv4(self):
        # validate_the_uptime_during_restarts()

    @pytest.mark.run(order=18)
    def test_017_verifing_Anycast_stop_DNS_OFF_behavior_ipv4(self):       
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
       
    @pytest.mark.run(order=19)
    def test_018_verifing_Anycast_start_DNS_OFF_behavior_ipv4(self): 
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

    @pytest.mark.run(order=20)
    def test_019_Verifying_Anycast_start_DNS_OFF_behavior_ipv4_killall(self):
        log("start","/infoblox/var/infoblox.log",config.grid_vip)
        #log("start","/var/log/messages",config.grid_vip)
        
        abnormally_kill_named()
        
        log("stop","/infoblox/var/infoblox.log",config.grid_vip)
        #log("stop","/var/log/messages",config.grid_vip)

        LookFor_info=[".*/infoblox/dns/bin/named_control).*killall named.*",".*/infoblox/dns/bin/named_control).*DNS not suppress splunk restart.*",".*/infoblox/dns/bin/named_control.*"]
        flag_info=0
        #flag_sys=0
        
        for look in LookFor_info:
            print(look)
            logs=logv(look,"/infoblox/var/infoblox.log",config.grid_vip)
            print(logs)
            if logs:
                flag_info=flag_info+1
            
        # for look in LookFor_sys:
            # print(look)

            # logs=logv(look,"/var/log/messages",config.grid_vip)
            # print(logs)
            # if logs:
                # flag_sys=flag_sys+1
        print(flag_info)   
        if flag_info==len(LookFor_info):
            assert True
        else:
            assert False
            