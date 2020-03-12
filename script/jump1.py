#!/usr/bin/env python3

import os
import paramiko

jumpbox_public_addr = '10.49.19.181'
jumpbox_private_addr = '172.16.10.254'
target_addr = '172.16.10.3'
jumpbox=paramiko.SSHClient()
jumpbox.set_missing_host_key_policy(paramiko.AutoAddPolicy())
jumpbox.connect(jumpbox_public_addr, username='centos')
jumpbox_transport = jumpbox.get_transport()
src_addr = (jumpbox_private_addr, 22)
dest_addr = (target_addr, 22)
jumpbox_channel = jumpbox_transport.open_channel("direct-tcpip", dest_addr, src_addr)
target=paramiko.SSHClient()
target.set_missing_host_key_policy(paramiko.AutoAddPolicy())
target.connect(target_addr, username='ubuntu',sock=jumpbox_channel)

stdin, stdout, stderr = target.exec_command("ip addr show dev eth0")
for line in stdout.read().split(b'\n'):
  print(str(line))

target.close()
jumpbox.close()
