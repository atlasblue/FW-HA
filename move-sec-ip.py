import requests
import time

USER_PC = 'admin'
SECRET_PC = ''
IP_PC = ''
NAME_FIREWALLVMS = ["XXX","XXX"]  
key = 'secondary_ip_address_list'

MAX_ALLOWED_NICS = 3
ERROR_TIMEOUT = 1
ERROR_MAX_ALLOWED_NICS = 2
ERROR_OTHER = 3

############################## Identify Secondary IP ###############################

def make_http_request(endpoint, method='GET', payload=None, username=USER_PC, secret=SECRET_PC):
    
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    response = requests.post(endpoint, json=payload, auth=(username, secret), verify=False)
    
    if not response.ok:
        response.raise_for_status()
        
    return response.json()


def get_vm_by_name(name, ip_pc):
    # Only gets first VM with matching name
    endpoint = 'https://{}:9440/api/nutanix/v3{}'.format(
        ip_pc,
        '/vms/list'
    )
    dict_payload = {
        'kind': 'vm',
        'length': 1,
        'filter': 'vm_name=={}'.format(name)
    }
    response = make_http_request(endpoint, method='POST', payload=dict_payload)
    if not response['entities']:
        return None
        
    return response['entities'][0]

def get_uuid_vm(name, ip_pc):
    vm = get_vm_by_name(name, ip_pc)
    uuid = vm['metadata']['uuid']
    return uuid
 
for name_vmfw in NAME_FIREWALLVMS:
  
    vm = get_vm_by_name(name_vmfw, IP_PC)
    
    del vm['status']
    for nic in vm['spec']['resources']['nic_list']:
        if key in nic:
            ip_secondary_address = nic['secondary_ip_address_list'][0]
            name_fw_with_address = name_vmfw
            name_nic_fw_with_address = nic['subnet_reference']['name']                   


uuid_fw_with_address = get_uuid_vm(name_fw_with_address, IP_PC)   
for fw in NAME_FIREWALLVMS:
    if fw != name_fw_with_address:
        name_fw_without_address = fw  
        
uuid_fw_without_address = get_uuid_vm(name_fw_without_address, IP_PC)

#print ("ip_secondary_address={}".format(ip_secondary_address))
#print ("name_fw_with_address={}".format(name_fw_with_address))
#print ("uuid_fw_with_address={}".format(uuid_fw_with_address))
#print ("name_nic_fw_with_address={}".format(name_nic_fw_with_address))
#print ("name_fw_without_address={}".format(name_fw_without_address))
#print ("uuid_fw_without_address={}".format(uuid_fw_without_address))

############################## Remove Secondary IP from Passive VM ###############################

PC_LOGIN = (IP_PC, USER_PC, SECRET_PC)

def make_http_request(endpoint, method='GET', payload=None, username=USER_PC, secret=SECRET_PC):
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    response = requests.request(method, endpoint, auth=(username,secret), json=payload, verify=False, headers=headers)
    
    if not response.ok:
        response.raise_for_status()
    return response.json()

def get_vm_by_name(name, ip_pc):
    # Only gets first VM with matching name
    endpoint = 'https://{}:9440/api/nutanix/v3{}'.format(
        ip_pc,
        '/vms/list'
    )
    dict_payload = {
        'kind': 'vm',
        'length': 1,
        'filter': 'vm_name=={}'.format(name)
    }
    response = make_http_request(endpoint, method='POST', payload=dict_payload)
    if not response['entities']:
        return None
    return response['entities'][0]

def get_vm_by_uuid(uuid, pc_login):
    ip_pc, user_pc, secret_pc = pc_login
    endpoint = "https://{}:9440/api/nutanix/v3{}".format(
        ip_pc,
        "/vms/{}".format(uuid)
    )
    return make_http_request(
        endpoint, method="GET", username=user_pc, secret=secret_pc
    )

def update_vm_details(vm_uuid, pc_login, dict_update):
    ip_pc, user_pc, secret_pc = pc_login
    endpoint = "https://{}:9440/api/nutanix/v3{}".format(
        ip_pc,
        "/vms/{}".format(vm_uuid),
    )
    return make_http_request(
        endpoint, method="PUT",
        payload=dict_update,
        username=user_pc, secret=secret_pc,
    )


def get_baseline_payload(vm_uuid, pc_login):
    dict_payload = get_vm_by_uuid(vm_uuid, pc_login)
    dict_payload.pop("status", None)
    return dict_payload


def delete_ip_in_nic(json_vm, name_subnet, ip_secondary_address):
    nic_list = json_vm['spec']['resources']['nic_list']
    new_sec_ip_address = ip_secondary_address
    for nic in nic_list:
        if (nic['subnet_reference']['name'] == name_subnet):
            if ('secondary_ip_address_list' in nic):
                del nic['secondary_ip_address_list']
    return json_vm

def get_ip_in_nic(json_vm, name_subnet, ip_secondary_address):
    nic_list = json_vm['spec']['resources'].get("nic_list")
    new_sec_ip_address = ip_secondary_address
    for i, nic in enumerate(nic_list):
        break
                
def wait_for_vm_update(vm_uuid, pc_login, sec_timeout=15, sec_retry=2):
    loop_count = 0
    loop_count_limit = int(sec_timeout / sec_retry)
    while True:
        vm = get_vm_by_uuid(vm_uuid, pc_login)
        if is_vm_done_updating(vm):
            return True, vm
        time.sleep(sec_retry)
        if loop_count > loop_count_limit:
            return False, vm
        loop_count += 1
    return False, vm

def is_vm_done_updating(vm):
    return vm["status"]["state"] in ("COMPLETE", "ERROR")  
    
def wait_for_vm_update(vm_uuid, pc_login, sec_timeout=15, sec_retry=2):
    loop_count = 0
    loop_count_limit = int(sec_timeout / sec_retry)
    while True:
        vm = get_vm_by_uuid(vm_uuid, pc_login)
        if is_vm_done_updating(vm):
            return True, vm
        time.sleep(sec_retry)
        if loop_count > loop_count_limit:
            return False, vm
        loop_count += 1
    return False, vm
    
vm = get_vm_by_uuid(uuid_fw_with_address, PC_LOGIN)
del vm['status']
print ("Updating VM(" + name_fw_with_address + ")...")
dict_payload = delete_ip_in_nic(vm, name_nic_fw_with_address, ip_secondary_address)
update_vm_details(uuid_fw_with_address, PC_LOGIN, dict_payload)

has_finished_updating, final_vm_state = wait_for_vm_update(
    uuid_fw_with_address, PC_LOGIN, sec_timeout=60, sec_retry=3
)

print ("Removed Secondary IP (" + ip_secondary_address + ") from VM(" + name_fw_with_address + ").")
print ("Sleeping for 10 secs to clear cache before reassignment")
time.sleep(10)


############################## Add Secondary IP to Active VM ###############################


VM_NAME = 'name_fw_without_address'
PC_LOGIN = (IP_PC, USER_PC, SECRET_PC)
MAX_ALLOWED_NICS = 3
ERROR_TIMEOUT = 1
ERROR_MAX_ALLOWED_NICS = 2
ERROR_OTHER = 3


def make_http_request(endpoint, method='GET', payload=None, username=USER_PC, secret=SECRET_PC):
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    
    response = requests.request(method,endpoint,auth=(username,secret), json=payload, verify=False, headers=headers)
    
    if not response.ok:
        response.raise_for_status()
    return response.json()


def get_vm_by_name(name, ip_pc):
    # Only gets first VM with matching name
    endpoint = 'https://{}:9440/api/nutanix/v3{}'.format(
        ip_pc,
        '/vms/list'
    )
    dict_payload = {
        'kind': 'vm',
        'length': 1,
        'filter': 'vm_name=={}'.format(name)
    }
    response = make_http_request(endpoint, method='POST', payload=dict_payload)
    if not response['entities']:
        return None
    return response['entities'][0]

def get_vm_by_uuid(uuid, pc_login):
    ip_pc, user_pc, secret_pc = pc_login
    endpoint = "https://{}:9440/api/nutanix/v3{}".format(
        ip_pc,
        "/vms/{}".format(uuid)
    )
    return make_http_request(
        endpoint, method="GET", username=user_pc, secret=secret_pc
    )

def update_vm_details(vm_uuid, pc_login, dict_update):
    ip_pc, user_pc, secret_pc = pc_login
    endpoint = "https://{}:9440/api/nutanix/v3{}".format(
        ip_pc,
        "/vms/{}".format(vm_uuid)
    )
    return make_http_request(
        endpoint, method="PUT",
        payload=dict_update,
        username=user_pc, secret=secret_pc
    )


def get_baseline_payload(vm_uuid, pc_login):
    dict_payload = get_vm_by_uuid(vm_uuid, pc_login)
    dict_payload.pop("status", None)
    return dict_payload


def update_ip_in_nic(json_vm, name_subnet, ip_secondary_address):
    json_vm['spec']['resources']['nic_list'][0]['secondary_ip_address_list'] = [ip_secondary_address]
    print (json_vm)
    return json_vm   


def get_ip_in_nic(json_vm, name_subnet, ip_secondary_address):
    nic_list = json_vm['spec']['resources'].get("nic_list")
    new_sec_ip_address = ip_secondary_address
    for i, nic in enumerate(nic_list):
        break
                
def wait_for_vm_update(vm_uuid, pc_login, sec_timeout=15, sec_retry=2):
    loop_count = 0
    loop_count_limit = int(sec_timeout / sec_retry)
    while True:
        vm = get_vm_by_uuid(vm_uuid, pc_login)
        if is_vm_done_updating(vm):
            return True, vm
        time.sleep(sec_retry)
        if loop_count > loop_count_limit:
            return False, vm
        loop_count += 1
    return False, vm

def is_vm_done_updating(vm):
    return vm["status"]["state"] in ("COMPLETE", "ERROR") 
  
  
vm = get_vm_by_uuid(uuid_fw_without_address, PC_LOGIN)
del vm['status']
print ("Updating VM(" + name_fw_without_address + ")...")
dict_payload = update_ip_in_nic(vm, name_nic_fw_with_address, ip_secondary_address)

update_vm_details(uuid_fw_without_address, PC_LOGIN, dict_payload)

has_finished_updating, final_vm_state = wait_for_vm_update(
    uuid_fw_without_address, PC_LOGIN, sec_timeout=60, sec_retry=3
)

print ("Added Secondary IP (" + ip_secondary_address + ") to (" + name_fw_without_address + ")")
