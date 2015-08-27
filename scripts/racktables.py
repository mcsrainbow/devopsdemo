#!/bin/env python
#-*- coding:utf-8 -*-

# Author: Dong Guo
# Last Modified: 2015/02/26

import os
import sys
from decimal import Decimal
import requests
from requests.auth import HTTPBasicAuth

# import urllib to encode the data for POST
from urllib import quote_plus

# torndb is a lightweight wrapper around MySQLdb
try:
    from torndb import Connection
except ImportError:
    sys.stderr.write("ERROR: Requires torndb, try 'yum install MySQL-python' then 'pip install torndb'.\n")
    sys.exit(1)

# racktables server address, database, username, password, headers, auth
rt_server = "real_rt_server"
rt_webuser = "real_rt_webuser"
rt_webpass = "real_rt_webpass"
rt_dbname = "real_rt_dbname"
rt_dbuser = "real_rt_dbuser"
rt_dbpass = "real_rt_dbpass"

rt_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
rt_auth = HTTPBasicAuth(rt_webuser, rt_webpass)

def parse_opts():
    """Help messages (-h, --help) for racktables.py"""

    import textwrap
    import argparse

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
        '''
        examples:
          {0} idc1-server1
          {0} idc1-server1 -r
          {0} idc1-server1 -d
          {0} idc1-server1 -w
          {0} idc1-server1 -w -s IDC1:P1:C1:1
          {0} idc1-server2 -o -w -s IDC1:P1:C1:2
          {0} idc1-server2 -o -r
          {0} idc2-server1 -w -s IDC2:P2:C1:1,2
          {0} idc2-server2 -w -s IDC2:P1:C2:34 -p left
          {0} idc2-server3 -w -s IDC2:P1:C2:34 -p right
          {0} BlankIDC2P1C2U9 -b -w -s IDC2:P1:C2:9
          {0} BlankIDC2P1C2U9 -b -d
          {0} IDC2:P1:C2 -l
        '''.format(__file__)
        ))
    exclusion = parser.add_mutually_exclusive_group()
    parser.add_argument('hostname', action="store", type=str)
    exclusion.add_argument('-r', action="store_true", default=False,help='read from database')
    exclusion.add_argument('-d', action="store_true", default=False,help='delete from database')
    exclusion.add_argument('-w', action="store_true", default=False,help='write to database')
    exclusion.add_argument('-l', action="store_true", default=False,help='list hosts and devices of the rackspace')
    parser.add_argument('-o', action="store_true", default=False,help='offline mode, skip the functions "isup","sum_info"')
    parser.add_argument('-b', action="store_true", default=False,help='set Type as PatchPanel')
    parser.add_argument('-s', metavar='rackspace', type=str, help='rackspace informations')
    parser.add_argument('-p', metavar='rackposition', type=str, choices=['left','right','front','interior','back'], help='rackspace detailed position')

    args = parser.parse_args()
    return {'hostname':args.hostname, 'read':args.r, 'delete':args.d, 'offline':args.o, 'blank':args.b, 'write':args.w, 'rackspace':args.s, 'rackposition':args.p, 'list':args.l }

class _AttributeString(str):
    """
    Simple string subclass to allow arbitrary attribute access.
    """
    @property
    def stdout(self):
        return str(self)

def remote(cmd, hostname, username, password=None, pkey=None, pkey_type="rsa", port=22):
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import paramiko

    p = paramiko.SSHClient()
    p.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if pkey is not None:
        if pkey_type == "dsa":
            pkey = paramiko.DSSKey.from_private_key_file(pkey)
        else:
            pkey = paramiko.RSAKey.from_private_key_file(pkey)
        p.connect(hostname=hostname, username=username, pkey=pkey, port=port)
    else:
        p.connect(hostname=hostname, username=username, password=password, port=port)

    (stdin, stdout, stderr) = p.exec_command(cmd)

    stdout_str=""
    stderr_str=""
    for line in stdout.readlines():
        stdout_str = stdout_str + line
    for line in stderr.readlines():
        stderr_str = stderr_str + line

    out = _AttributeString(stdout_str.strip() if stdout else "")
    err = _AttributeString(stderr_str.strip() if stderr else "")

    out.cmd = cmd
    out.failed = False
    out.return_code = stdout.channel.recv_exit_status()
    out.stderr = err
    if out.return_code != 0:
        out.failed = True
    out.succeeded = not out.failed

    p.close()
    return out

def run(cmd,hostname=False):
    if not hostname:
        hostname = opts['hostname']

    username = "username"
    pkey = "/home/username/.ssh/id_rsa"
    pkey_type = 'dsa'

    out = remote(cmd, hostname=hostname, username=username, pkey=pkey, pkey_type=pkey_type)

    return out

def sudo(cmd,hostname=False):
    cmd_sudo = 'sudo ' + cmd

    if not hostname:
        out = run(cmd_sudo)
    else:
        out = run(cmd_sudo,hostname)

    return out

def isup(host):
    """Check if host is up"""

    import socket

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(1)
    try:
        conn.connect((host,22))
        conn.close()
    except:
        print "Failed to connect to host {0} port 22: Network is unreachable".format(host)
        return False
    return True

class GetServerInfo(object):
    """Remotely get informations"""
    
    def __init__(self):
        pass

    def get_server_type(self):
        xapi_sign = run('rpm -q --quiet xapi-xe')
        if xapi_sign.succeeded:
            return "XenServer"
         
        ec2_sign = run("""curl http://169.254.169.254/latest/meta-data/hostname --connect-timeout 1 |egrep -wq 'ec2.internal|compute.internal'""")
        if ec2_sign.succeeded:
            return "EC2"
    
        xen_sign = run('ps -e | egrep -wq "xenbus|xenwatch"')
        if xen_sign.succeeded:
            return "VM"
        
        return "Server"
        
    def get_fqdn(self):
        hostname = run('hostname |cut -d. -f1')
        fqdn = run('hostname -f')
        if fqdn.failed:
            fqdn = hostname
        return fqdn
    
    def get_os_release(self):
        os_release = run('cat /etc/*-release |head -n 1 |cut -d= -f2 |sed s/\\"//g')
    
        os_mode = run('uname -m')
        return os_release + ", " + os_mode
    
    def get_memory(self):
        output = run("""grep -w "MemTotal" /proc/meminfo |awk '{print $2}'""")
        t_mem_g = Decimal(output) / 1024 / 1024
        return round(t_mem_g,2)
    
    def get_swap(self):
        output = run("""grep -w "SwapTotal" /proc/meminfo |awk '{print $2}'""")
        t_swap_g = Decimal(output) / 1024 /1024
        return round(t_swap_g,2)
    
    def get_cpu(self):
        cpu_type = run("""grep 'model name' /proc/cpuinfo |uniq |awk -F : '{print $2}' |sed 's/^[ \t]*//g' |sed 's/ \+/ /g'""")
        cpu_cores = run("""grep 'processor' /proc/cpuinfo |sort |uniq |wc -l""")
        return {'cpu_cores':cpu_cores, 'cpu_type':cpu_type}
    
    def get_disk(self):
        disk = sudo("""fdisk -l 2>/dev/null |grep -v "/dev/mapper" |grep "Disk /dev" |awk '{print $2" "$3" "$4}'|grep -Ev '^$|^doesn' |sort |xargs""")
        return disk
    
    def get_network(self):
        output = run("""/sbin/ifconfig |grep "Link encap" |awk '{print $1}' |grep -wv 'lo' |xargs""")
        nics = output.split()
        t_nic_info = ""
        for i in nics:
            ipaddr = run("""/sbin/ifconfig %s |grep -w "inet addr" |cut -d: -f2 | awk '{print $1}'""" % (i))
            if ipaddr:
                t_nic_info = t_nic_info + i + ":" + ipaddr + ", "
        return t_nic_info
    
    def get_vm_list(self):
        output = sudo("""xl list-vm |awk '{print $3}' |grep -vw name |sort -n |xargs""")
        vm_list = ','.join(output.split())
        return vm_list
    
    def get_rst_on(self):
        colo_prefix = run("""hostname -s |egrep 'idc1-|idc2-' |cut -d- -f1""")
        xs_pool_master = colo_prefix + '-xenserver1'

        if not isup(xs_pool_master):
            return False

        vm_uuid = sudo("""xe vm-list |grep -B1 -w %s |awk '{if ($1 == "uuid") print $NF}'""" % (opts['hostname']),hostname=xs_pool_master)
        rst_uuid = sudo("""xe vm-param-get uuid={0} param-name=resident-on""".format(vm_uuid),hostname=xs_pool_master)
        rst_name = sudo("""xe vm-list params |egrep 'name-label|resident-on' |grep -B1 %s |grep -w "Control domain" |awk -F ": " '{print $NF}' |cut -d. -f1""" % (rst_uuid),hostname=xs_pool_master)
        return rst_name

    def get_xs_memory(self):
        t_mem_m = sudo('xl info |grep total_memory |cut -d : -f 2')
        t_mem_g = int(t_mem_m) / 1024
        return t_mem_g
    
    def get_xs_cpu(self):
        cpu_cores = sudo("""xe host-cpu-info |grep -w cpu_count |awk -F ': ' '{print $2}'""")
        cpu_type = run("""grep 'model name' /proc/cpuinfo |uniq |awk -F : '{print $2}' |sed 's/^[ \t]*//g' |sed 's/ \+/ /g'""")
        return {'cpu_cores':cpu_cores, 'cpu_type':cpu_type}
    
    def get_ec2_pubname(self):
        ec2_pubname = run("""curl http://169.254.169.254/latest/meta-data/public-hostname --connect-timeout 1""")
        return ec2_pubname

def sum_info():
    """Get & Print all informations"""

    server_info = GetServerInfo()

    server_type = server_info.get_server_type()
    print "TYPE:        " + server_type

    fqdn = server_info.get_fqdn()
    print "FQDN:        " + fqdn

    os_release = server_info.get_os_release()
    print "OS:          " + os_release

    if server_type == "XenServer":
        memory = server_info.get_xs_memory()
    else:
        memory = server_info.get_memory()
    print "MEMORY:      " + str(memory) + " GB"

    swap = server_info.get_swap()
    print "SWAP:        " + str(swap) + " GB"

    if server_type == "XenServer":
        cpu_info = server_info.get_xs_cpu()
    else:
        cpu_info = server_info.get_cpu()
    print "CPU:         " + cpu_info['cpu_cores'] + " Cores, " + cpu_info['cpu_type']

    disk = server_info.get_disk()
    print "DISK:        " + disk

    network = server_info.get_network()
    print "NETWORK:     " + network

    vm_list = ""
    if server_type == "XenServer":
        vm_list = server_info.get_vm_list()
        print "VMLIST:      " + vm_list

    xs_name = ""
    if server_type == "VM":
        xs_name = server_info.get_rst_on()
        print "RESIDENT-ON: " + xs_name 

    ec2_pubname = ""
    if server_type == "EC2":
        ec2_pubname = server_info.get_ec2_pubname()
        print "PUBNAME:     " + ec2_pubname
    
    return {'server_type':server_type, 'fqdn':fqdn, 'hostname':opts['hostname'],'os_release':os_release,
            'memory':memory,'swap':swap, 'cpu_cores':cpu_info['cpu_cores'], 'cpu_type':cpu_info['cpu_type'],
            'disk':disk,'network':network, 'vm_list':vm_list, 'resident_on':xs_name, 'ec2_pubname':ec2_pubname}

def read_db(info):
    """Get info from Racktables DB"""

    # connect to racktables db
    db = Connection(rt_server,rt_dbname,rt_dbuser,rt_dbpass)

    # check if object_id already exists
    object_id = ""
    for item in db.query("select * from Object where name='{0}'".format(info['hostname'])):
        object_id = item.id
    if not object_id:
        print "Object:{0} does not exist".format(info['hostname'])
        return False
    
    # get the location info
    rack_id_list = []
    unit_no_list = []
    for item in db.query("select rack_id,unit_no from RackSpace where object_id=(select id from Object where name='{0}')".format(info['hostname'])):
        rack_id_list.append(int(item.rack_id))
        unit_no_list.append(int(item.unit_no))
    if not item:
        print "Object:{0} does not have location info".format(info['hostname'])
        return False
    rack_id = ','.join(str(i) for i in list(set(rack_id_list)))
    unit_no = ','.join(str(i) for i in list(set(unit_no_list)))

    for item in db.query("select location_name,row_name,name from Rack where id='{0}'".format(rack_id)):
        location_name = item.location_name
        row_name = item.row_name
        rack_name = item.name
    print "RACKSPACE:   {0}:{1}:{2}:{3}".format(location_name,row_name,rack_name,unit_no)

    # close db
    db.close()

    return {'location_name':location_name, 'row_name':row_name, 'rack_name':rack_name, 'unit_no':unit_no}

def update_db(info):
    """Automate server audit into Racktables"""

    # connect to racktables db
    db = Connection(rt_server,rt_dbname,rt_dbuser,rt_dbpass)

    # get object_type_id
    for item in db.query("select * from Dictionary where dict_value='{0}'".format(info['server_type'])):
        object_type_id = item.dict_key
    
    # delete object if already exists
    delete_object(info)   
 
    # create object
    url = """http://{0}/racktables/index.php?module=redirect&page=depot&tab=addmore&op=addObjects""".format(rt_server)
    if info['server_type'] in ["Server","XenServer"]:
        payload = """0_object_type_id={0}&0_object_name={1}&0_object_label=&0_object_asset_no={1}&got_fast_data=Go%21"""\
                  .format(object_type_id,info['hostname'])
    if info['server_type'] in ["VM","EC2"]:
        payload = """virtual_objects=&0_object_type_id={0}&0_object_name={1}&got_fast_data=Go%21"""\
                  .format(object_type_id,info['hostname'])

    req = requests.post(url, data=payload, headers=rt_headers, auth=rt_auth)
    if req.status_code != requests.codes.ok:
        print "Failed to create object: {0}".format(info['hostname'])
        return False
    else:
        print "OK - Created object: {0}".format(info['hostname'])

    object_id = ""
    # get object_id
    for item in db.query("select * from Object where name='{0}'".format(info['hostname'])):
        object_id = item.id
    if not object_id:
        print "Failed to get object_id"
        return False

    # get os_release_id
    os_release_key = ""
    for item in db.query("select * from Dictionary where dict_value='{0}'".format(info['os_release'])):
        os_release_key = item.dict_key
    if not os_release_key:
        print "Failed to get object_type_id, please add '{0}' to 'Configuration - Dictionary - Server OS type'.".format(info['os_release'])
        return False

    # update the informations of object, all post data formats were got by firebug on firefox
    url = """http://{0}/racktables/index.php?module=redirect&page=object&tab=edit&op=update""".format(rt_server)
    if info['server_type'] == "Server":
        payload = """object_id={0}&object_type_id={1}&object_name={2}&object_label=&object_asset_no={2}&0_attr_id=14&0_value=&1_attr_id=10000&1_value={3}\
&2_attr_id=10004&2_value={4}&3_attr_id=3&3_value={5}&4_attr_id=2&4_value=0&5_attr_id=26&5_value=0&6_attr_id=10006&6_value={6}\
&7_attr_id=10003&7_value={7}&8_attr_id=1&8_value=&9_attr_id=28&9_value=&10_attr_id=21&10_value=&11_attr_id=4&11_value={8}\
&12_attr_id=24&12_value=&13_attr_id=10005&13_value={9}&14_attr_id=25&14_value=&num_attrs=15&object_comment=&submit.x=15&submit.y=13"""\
                  .format(object_id,object_type_id,info['hostname'],info['cpu_cores'],quote_plus(info['disk']),info['fqdn'],
                          info['memory'],quote_plus(info['network']),os_release_key,info['swap'])
    if info['server_type'] == "XenServer":
        payload = """object_id={0}&object_type_id={1}&object_name={2}&object_label=&object_asset_no={2}&0_attr_id=14&0_value=&1_attr_id=10000&1_value={3}\
&2_attr_id=10004&2_value={4}&3_attr_id=3&3_value={5}&4_attr_id=26&4_value=0&5_attr_id=10006&5_value={6}&6_attr_id=10003&6_value={7}\
&7_attr_id=1&7_value=&8_attr_id=28&8_value=&9_attr_id=4&9_value={8}&10_attr_id=24&10_value=&11_attr_id=10005&11_value={9}\
&12_attr_id=25&12_value=&13_attr_id=10008&13_value={10}&num_attrs=14&object_comment=&submit.x=18&submit.y=21"""\
                  .format(object_id,object_type_id,info['hostname'],info['cpu_cores'],quote_plus(info['disk']),info['fqdn'],
                          info['memory'],quote_plus(info['network']),os_release_key,info['swap'],quote_plus(info['vm_list']))
    if info['server_type'] == "EC2":
        payload = """object_id={0}&object_type_id={1}&object_name={2}&object_label=&object_asset_no=&0_attr_id=14&0_value=&1_attr_id=10000&1_value={3}\
&2_attr_id=10004&2_value={4}&3_attr_id=3&3_value={5}&4_attr_id=26&4_value=0&5_attr_id=10006&5_value={6}&6_attr_id=10003&6_value={7}\
&7_attr_id=10010&7_value={8}&8_attr_id=4&8_value={9}&9_attr_id=24&9_value=&10_attr_id=10005&10_value={10}&num_attrs=11&object_comment=&submit.x=19&submit.y=27"""\
                  .format(object_id,object_type_id,info['hostname'],info['cpu_cores'],quote_plus(info['disk']),info['fqdn'],
                          info['memory'],quote_plus(info['network']),info['ec2_pubname'],os_release_key,info['swap'])
    if info['server_type'] == "VM":
        payload = """object_id={0}&object_type_id={1}&object_name={2}&object_label=&object_asset_no=&0_attr_id=14&0_value=&1_attr_id=10000&1_value={3}\
&2_attr_id=10004&2_value={4}&3_attr_id=3&3_value={5}&4_attr_id=26&4_value=0&5_attr_id=10006&5_value={6}&6_attr_id=10003&6_value={7}\
&7_attr_id=10007&7_value={8}&8_attr_id=4&8_value={9}&9_attr_id=24&9_value=&10_attr_id=10005&10_value={10}&num_attrs=11&object_comment=&submit.x=25&submit.y=14'"""\
                  .format(object_id,object_type_id,info['hostname'],info['cpu_cores'],quote_plus(info['disk']),info['fqdn'],
                          info['memory'],quote_plus(info['network']),info['resident_on'],os_release_key,info['swap']) 

    req = requests.post(url, data=payload, headers=rt_headers, auth=rt_auth)
    if req.status_code != requests.codes.ok:
        print "Failed to update attributes"
        return False
    print "OK - Updated attributes"

    # ec2 servers don't need to update the ip pool
    if info['server_type'] not in ["EC2"]:
        # update the ip pool
        nics = ("".join(info['network'].split())).split(',')
        for i in nics:
            nic_info = i.split(':')
            nic_name = "".join(nic_info[0:1])
            nic_addr = "".join(nic_info[1:2])
            # check if nic_name is not correct
            if nic_name.isalnum():
                # create nic
                url = """http://{0}/racktables/index.php?module=redirect&page=object&tab=ip&op=add""".format(rt_server)
                payload = """object_id={0}&bond_name={1}&ip={2}&bond_type=regular&submit.x=11&submit.y=6"""\
                          .format(object_id,nic_name,nic_addr)
                req = requests.post(url, data=payload, headers=rt_headers, auth=rt_auth)
                if req.status_code != requests.codes.ok:
                    print "Failed to update ip pool for {0}:{1}".format(nic_name,nic_addr)
                    return False
                print "OK - Updated ip pool for {0}:{1}".format(nic_name,nic_addr)

    # virtual servers don't need to update the rackspace
    if info['server_type'] not in ["EC2","VM"]:
        # update rack info
        update_rack(info,object_id)

    # close db
    db.close()

    # end
    return True

def update_blank_offline(info):
    """Automate server autodir for PatchPanel into Racktables or as offline mode"""

    # connect to racktables db
    db = Connection(rt_server,rt_dbname,rt_dbuser,rt_dbpass)

    # delete object if already exists
    delete_object(info)

    # create object
    url = """http://{0}/racktables/index.php?module=redirect&page=depot&tab=addmore&op=addObjects""".format(rt_server)
    if opts['blank']:
        payload = """0_object_type_id=9&0_object_name={0}&0_object_label=&0_object_asset_no={0}&got_fast_data=Go%21"""\
                  .format(info['hostname'])
    if opts['offline']:
        payload = """0_object_type_id=4&0_object_name={0}&0_object_label=&0_object_asset_no={0}&got_fast_data=Go%21"""\
                  .format(info['hostname'])

    req = requests.post(url, data=payload, headers=rt_headers, auth=rt_auth)
    if req.status_code != requests.codes.ok:
        print "Failed to create object: {0}".format(info['hostname'])
        return False
    else:
        print "OK - Created object: {0}".format(info['hostname'])

    # get object_id
    for item in db.query("select * from Object where name='{0}'".format(info['hostname'])):
        object_id = item.id
    if not object_id:
        print "Failed to get object_id"
        return False

    # update rack info
    update_rack(info,object_id)

    # close db
    db.close()

    # end
    return True

def update_rack(info,object_id):
    """Automate server audit for rack info into Racktables"""

    # connect to racktables db
    db = Connection(rt_server,rt_dbname,rt_dbuser,rt_dbpass)

    # update the rackspace
    if opts['rackspace']:
        rs_info = opts['rackspace'].split(':')
        colo = "".join(rs_info[0:1])
        row  = "".join(rs_info[1:2])
        rack = "".join(rs_info[2:3])
        atom = "".join(rs_info[3:4])
        if not atom:
            print "The rackspace is not correct"
            return False 

        # get rack_id
        for item in db.query("select * from Rack where name = '{0}' and location_name = '{1}' and row_name = '{2}'".format(rack,colo,row)):
            rack_id = item.id
        if not rack_id:
            print "Failed to get rack_id"
            return False
        
        atom_list = atom.split(',')
        atom_data  = []
        for i in atom_list:
           if opts['rackposition']:
               if opts['rackposition'] in ['left', 'front']:
                   atom_data.append("&atom_{0}_{1}_0=on".format(rack_id,i))
               if opts['rackposition'] in ['right', 'back']:
                   atom_data.append("&atom_{0}_{1}_2=on".format(rack_id,i))
               if opts['rackposition'] in ['interior']:
                   atom_data.append("&atom_{0}_{1}_1=on".format(rack_id,i))
           else:
               atom_data.append("&atom_{0}_{1}_0=on&atom_{0}_{1}_1=on&atom_{0}_{1}_2=on".format(rack_id,i))
        atom_url = "".join(atom_data) 

        url = """http://{0}/racktables/index.php?module=redirect&page=object&tab=rackspace&op=updateObjectAllocation""".format(rt_server)
        payload = """object_id={0}&rackmulti%5B%5D={1}&comment=&got_atoms=Save{2}"""\
                  .format(object_id,rack_id,atom_url)
        req = requests.post(url, data=payload, headers=rt_headers, auth=rt_auth)
        if req.status_code != requests.codes.ok:
            print "Failed to update rackspace"
            return False
        print "OK - Updated rackspace"
           
    # close db
    db.close()

    # end
    return True

def delete_object(info):
    """Delete object from DB"""

    # connect to racktables db
    db = Connection(rt_server,rt_dbname,rt_dbuser,rt_dbpass)

    # check if object_id already exists, then create object if not
    object_id = ""
    for item in db.query("select * from Object where name='{0}'".format(info['hostname'])):
        object_id = item.id

    # delete object if already exists
    if object_id:
        url = """http://{0}/racktables/index.php?module=redirect&op=deleteObject&page=depot&tab=addmore&object_id={1}"""\
              .format(rt_server,object_id)
        req = requests.get(url,auth=rt_auth)
        if req.status_code != requests.codes.ok:
            print "Failed to delete the existing object: {0}".format(info['hostname'])
            return False
        else:
            print "OK - Deleted the existing object: {0}".format(info['hostname'])

    # close db
    db.close()
    
    return True

def list_object(info):
    """List the objects of the given rackspace"""

    # connect to racktables db
    db = Connection(rt_server,rt_dbname,rt_dbuser,rt_dbpass)

    # check if rackspace is correct
    rs_info = opts['hostname'].split(':')
    colo = "".join(rs_info[0:1])
    row  = "".join(rs_info[1:2])
    rack = "".join(rs_info[2:3])
    if not rack:
        print "The rackspace is not correct"
        return False

    # get rack_id
    for item in db.query("select * from Rack where name = '{0}' and location_name = '{1}' and row_name = '{2}'".format(rack,colo,row)):
        rack_id = item.id
    if not rack_id:
        print "Failed to get rack_id"
        return False

    # get object_id
    object_id_list = []
    for item in db.query("select * from RackSpace where rack_id={0}".format(rack_id)):
        object_id_list.append(item.object_id)
    if len(object_id_list) == 0:
        print "Failed to get object_id"
        return False

    # get rid of the duplicated items then sort and read one by one
    for object_id in sorted(list(set(object_id_list))):
        for item in db.query("select * from Object where id={0}".format(object_id)):
            object_name = item.name
            object_type_id = item.objtype_id
            for item in db.query("select * from Dictionary where dict_key={0}".format(object_type_id)):
                object_type_name = item.dict_value
        print "{0}: {1}".format(object_type_name,object_name)

    # close db
    db.close()
    
    return True

if __name__=='__main__':
    # show help messages if no parameter
    argv_len = len(sys.argv)
    if argv_len < 2:
        os.system(__file__ + " -h")
        sys.exit(1)
    opts = parse_opts()

    if not opts['blank'] and not opts['list'] and not opts['offline']:
        # check if host is up
        hostup = isup(opts['hostname'])
        
        if hostup: 
            # get info
            print "========================================"
            print "Getting informations from '{0}'...".format(opts['hostname'])
            print "========================================"
            info = sum_info()
 
            # update racktables
            if opts['write']:
                print "========================================"
                print "Updating racktables..." 
                print "========================================"
                update_db(info)
        else:
            info = {'hostname':opts['hostname']}
    else:
        info = {'hostname':opts['hostname']}
        if opts['blank'] or opts['offline']:
            if opts['write']:
                print "========================================"
                print "Updating racktables..." 
                print "========================================"
                update_blank_offline(info) 
        if opts['list']:
            print "========================================"
            print "Getting objects in rackspace:'{0}'...".format(opts['hostname'])
            print "========================================"
            list_object(info)

    # read racktables
    if opts['read'] or opts['delete']:
        print "========================================"
        print "Getting informations from DB..." 
        print "========================================"
        read_db(info)

    # delete object from db
    if opts['delete']:
        print "========================================"
        print "Deleting Object: '{0}' from DB...".format(opts['hostname'])
        print "========================================"
        delete_object(info)
