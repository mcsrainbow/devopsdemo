#!/bin/env python

'''
A simple interface to execute shell commands.
Reference: fabric/operations.py.

Examples:
    >>> from operations import local,remote,get,put

    >>> out = local('uname -r')
    >>> print out
    2.6.32
    >>> print out.stdout
    2.6.32
    >>> print out.failed
    False
    >>> print out.succeeded
    True

    >>> out = remote('hostname --fqdn',hostname='heylinux.com',username='jobs',
                     pkey='/path/to/rsa',port=8022)
    >>> print out
    heylinux.com
    >>> print out.failed
    False
    >>> print out.succeeded
    True

    >>> out = get('/tmp/remote.txt','/tmp/local.txt',hostname='heylinux.com',username='jobs',
                  pkey='/path/to/dsa',pkey_type='dsa',port=8022)
    >>> print out.failed
    True 
    >>> print out.succeeded
    False 
    >>> print out.stderr
    No such file or directory

    >>> out = put('/tmp/local.txt','/tmp/remote.txt',hostname='heylinux.com',username='jobs',
                  password='apple')
    >>> print out.failed
    False
    >>> print out.succeeded
    True
'''

import subprocess
import paramiko

class _AttributeString(str):
    """
    Simple string subclass to allow arbitrary attribute access.
    """
    @property
    def stdout(self):
        return str(self)

def local(cmd, capture=True, shell=None):
    out_stream = subprocess.PIPE
    err_stream = subprocess.PIPE
    p = subprocess.Popen(cmd, shell=True, stdout=out_stream, stderr=err_stream, executable=shell)
    (stdout, stderr) = p.communicate()

    out = _AttributeString(stdout.strip() if stdout else "")
    err = _AttributeString(stderr.strip() if stderr else "")

    out.cmd = cmd
    out.failed = False
    out.return_code = p.returncode
    out.stderr = err
    if out.return_code != 0:
        out.failed = True
    out.succeeded = not out.failed

    return out

def remote(cmd, hostname, username, password=None, pkey=None, pkey_type="rsa", port=22):
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

def sftp(src_path, dest_path, hostname, username, password=None, pkey=None, pkey_type="rsa", 
         port=22, transfer_type=None):
    p = paramiko.Transport((hostname,port))

    if pkey is not None:
        if pkey_type == "dsa":
            pkey = paramiko.DSSKey.from_private_key_file(pkey)
        else:
            pkey = paramiko.RSAKey.from_private_key_file(pkey)
        p.connect(username=username, pkey=pkey)
    else:
        p.connect(username=username, password=password)

    sftp = paramiko.SFTPClient.from_transport(p)

    out = _AttributeString()
    out.failed = False
    out.stderr = None
    
    if transfer_type is not None:
        try:
            if transfer_type == "get":
                sftp.get(src_path, dest_path)
            if transfer_type == "put":
                sftp.put(src_path, dest_path)
        except Exception, e:
            out.failed = True
            out.stderr = e.args[1]

    out.succeeded = not out.failed

    p.close()
    return out

def get(remote_path, local_path, hostname, username, password=None, pkey=None, pkey_type="rsa", port=22):
    return sftp(remote_path, local_path, hostname, username, password=password, pkey=pkey, pkey_type=pkey_type, 
                port=port, transfer_type="get")

def put(local_path, remote_path, hostname, username, password=None, pkey=None, pkey_type="rsa", port=22):
    return sftp(local_path, remote_path, hostname, username, password=password, pkey=pkey, pkey_type=pkey_type, 
                port=port, transfer_type="put")
