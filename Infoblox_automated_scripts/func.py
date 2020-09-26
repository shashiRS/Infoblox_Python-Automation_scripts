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
    data="killall named"
    stdin, stdout, stderr = client.exec_command(data)
    stdout=stdout.read()
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
        
        
test_001_ospf_for_advertising_ipv4
test_002_anycast_ipv4_configuration
test_020_ospf_for_advertising_ipv6
test_021_anycast_ipv6_configuration
test_034_bgp_for_advertising
test_035_anycast_ipv4_configuration
test_048_anycast_ipv6_configuration_BGP
test_061_parental_and_subscriber_configuration_setup



    @pytest.mark.run(order=90)
    def test_089_GMC_grid_master_condidate_ON_behaviour(self):   
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
            
            
    @pytest.mark.run(order=91)
    def test_090_GMC_grid_master_condidate_OFF_behaviour(self):
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

 
    @pytest.mark.run(order=92)
    def test_091_GMC_promote_HA_as_master_candidate(self):
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
            
            
    @pytest.mark.run(order=92)
    def test_091_GMC_promoted_master_candidate_ON_behaviour(self):
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
            
    @pytest.mark.run(order=93)
    def test_092_GMC_promoted_master_candidate_OFF_behaviour(self):
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


    @pytest.mark.run(order=93)
    def test_092_(self):
    
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no admin@'+config.grid_vip)
        try:
            child.logfile=sys.stdout
            child.expect('password:')
            child.sendline('infoblox')
            child.expect('Infoblox >')
            child.sendline('set restart_anycast_with_dns_restart on zone_loadout_time')
            child.expect('>')
            child.close() 
            assert True
            
        except Exception as e:
            child.close()
            print("Failure: Con't perform restart anycast off")
            print (e)
            assert False

    
 
----------------------------------------------------------------

    @pytest.mark.run(order=93)
    def test_000_Execute_cli_for_member(self):
    
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


    @pytest.mark.run(order=93)
    def test_000_Execute_cli_without_anycast_services(self):
    
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
            print("Failure: Can't perform restart anycast on/off")
            print (e)
            assert False


    @pytest.mark.run(order=32)
    def test_031_restart_anycast_ON_behavior_ibflex(self):
        set_restart_anycast_on()           

    @pytest.mark.run(order=33)
    def test_032_verifing_Anycast_restart_DNS_normally_ON_behavior_ibflex(self): 
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


    @pytest.mark.run(order=34)
    def test_033_verifing_Anycast_restart_DNS_ON_behavior_ibflex(self): 
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

        
    @pytest.mark.run(order=35)
    def test_034_Verifying_Anycast_stop_DNS_ON_behavior_ibflex(self):
    
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
            
          
    @pytest.mark.run(order=36)
    def test_035_Verifying_Anycast_start_DNS_ON_behavior_ibflex(self):
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
        
    @pytest.mark.run(order=37)
    def test_036_stop_anycast_OFF_behavior_zone(self):
        set_restart_anycast_off()
        

    @pytest.mark.run(order=38)
    def test_037_verifing_Anycast_restart_DNS_normally_OFF_behavior_ibflex(self): 
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


    @pytest.mark.run(order=39)
    def test_038_verifing_Anycast_restart_DNS_OFF_behavior_ibflex(self):
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


            
         
    @pytest.mark.run(order=40)
    def test_039_verifing_Anycast_stop_DNS_OFF_behavior_ibflex(self):
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
       
    @pytest.mark.run(order=41)
    def test_040_verifing_Anycast_start_DNS_OFF_behavior_ibflex(self): 
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
    
    
    
    @pytest.mark.run(order=84)
    def test_083_audit_log_should_contain_the_log_ON_behavior(self):
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

    @pytest.mark.run(order=84)
    def test_083_audit_log_should_contain_the_log_OFF_behavior(self):
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