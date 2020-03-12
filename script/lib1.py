#!/usr/bin/env python3
# this library is used to create configuration files to run VM (Centos/Ubuntu) and Junos (VMX/VQFX) on VMM (juniper internal cloud)
# created by mochammad irzan irzan@juniper.net
# 20 october 2019

import sys
import os
import param1
import shutil
import paramiko
import pexpect
import time
 
# from jnpr.junos import Device
# from jnpr.junos.utils.config import Config
from passlib.hash import md5_crypt
def check_ubuntu1804(d1):
	vm_list=d1['vm'].keys()
	vm_exist=[]
	for i in d1['vm'].keys():
		if d1['vm'][i]['os']=='ubuntu1804':
			vm_exist.append(i)
	if vm_exist:
		print("there is ubuntu 1804 as VM, please run \"vmm.py config\"")

def upload1(gw_external_ip,gw_internal_ip,i,d1):
	for j in d1['vm'][i]['interfaces'].keys():
		if d1['vm'][i]['interfaces'][j]['bridge']=='mgmt':
				target_addr=d1['vm'][i]['interfaces'][j]['ipv4'].split("/")[0]
	# print("GW external IP ",gw_external_ip)
	# print("GW internal IP ",gw_internal_ip)
	# print("Target ",target_addr)
	gw=paramiko.SSHClient()
	gw.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	gw.connect(gw_external_ip,username='centos')
	gw_transport=gw.get_transport()
	src_addr = (gw_internal_ip, 22)
	dest_addr = (target_addr, 22)
	gw_channel = gw_transport.open_channel("direct-tcpip", dest_addr, src_addr)
	target=paramiko.SSHClient()
	target.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	target.connect(target_addr, username='ubuntu',sock=gw_channel)
	scp1=target.open_sftp()
	scp1.put("./tmp/interfaces." + i,"interfaces")
	scp1.close()
	target.close()
	gw.close()


def get_private_ip_gw(d1):
	for i in d1['vm'].keys():
		if d1['vm'][i]['type']=="gw":
			for j in d1['vm'][i]['interfaces'].keys():
				if d1['vm'][i]['interfaces'][j]['bridge']=="mgmt":
					retval= d1['vm'][i]['interfaces'][j]['ipv4'].split("/")[0]
	return retval

def config_ubuntu1804(d1):
	print("upload configuration into VM ubuntu 1804")
	vm_list=d1['vm'].keys()
	vm_exist=[]
	for i in d1['vm'].keys():
		if d1['vm'][i]['os']=='ubuntu1804':
			vm_exist.append(i)
	if vm_exist:
		gw_external_ip=get_ip_vm(d1,'gw')
		gw_internal_ip=get_private_ip_gw(d1)
		for i in vm_exist:
			print("setting config for  ",i)
			serial_vm=get_serial_vm(d1,i)
			host1,port1=serial_vm.split(":")
			cmd1="telnet " + host1 + " " + port1
			ip_addr=d1['vm'][i]['interfaces']['em0']['ipv4']
			cmd2=['sudo ip addr add dev eth0 ' + ip_addr]
			cmd2.append('sudo ip link set dev eth0 up')
			cmd2.append("rm -rf ~/.ssh")
			cmd2.append("mkdir ~/.ssh")
			cmd2.append("echo \"" + d1['vmm_pod']['junos_login']['ssh_key'] + " \" > ~/.ssh/authorized_keys")
			# cmd2.append("sudo echo \" + i  + "\" 
			cmd2.append("echo " + i + " > ~/hostname")
			cmd2.append("sudo mv ~/hostname /etc/hostname");
			p1=pexpect.spawn(cmd1)
			p1.sendline("ubuntu")
			p1.expect("Password:")
			p1.sendline("pass01")
			p1.expect("$")
			# print("setting ip")
			for j in cmd2:
				p1.sendline(j)
				p1.expect("$")
			p1.sendline("exit")
			p1.expect("login:")
			# print("done")
			p1.close()
			upload1(gw_external_ip,gw_internal_ip,i,d1)
			cmd2=["sudo rm /etc/netplan/*"]
			cmd2.append("sudo cp ~/interfaces /etc/netplan/50-config.yaml")
			# cmd2.append("sudo reboot")
			p1=pexpect.spawn(cmd1)
			p1.sendline("ubuntu")
			p1.expect("Password:")
			p1.sendline("pass01")
			p1.expect("$")
			for j in cmd2:
				p1.sendline(j)
				p1.expect("$")
			p1.sendline("sudo reboot")
			time.sleep(1)
			# p1.sendline("exit")
			# p1.expect("login:")
			# print("done")
			p1.close()
	else:
		print("no ubuntu1804 in the topology")

def print_syntax():
	print("usage : vmm.py [-c config_file] <command>")
	print("commands are : ")
	print("  upload : to upload configuration to vmm pod ")
	print("  start  : to start VM in the vmm pod")
	print("  stop   : to stop in the vmm pod")
	print("  list   : list of running VM")
	print("  get_serial : get serial information of the vm")
	print("  get_vga : get vga information of the vm (for vnc)")
	print("  get_ip  : get IP information of the vm")
	print("if configuration file is not specified, then file lab.yaml must be present")

def check_argv(argv):
	retval={}
	cmd_list=['upload','start','stop','get_serial','get_vga','get_ip','list','config']
	if len(argv) == 1:
		print_syntax()
	else:
		if "-c" not in argv:
			if not os.path.isfile("./lab.yaml"):
				print("file lab.conf doesn't exist, please create one or define another file for configuration")
				config_file="oldlab.yaml"
			else:
				config_file="lab.yaml"
		else:
			config_file="lab.yaml"
		retval['config_file']=config_file
		retval['cmd']=argv[1]
		if retval['cmd'] == 'get_ip' and len(argv)==2:
			print("get_ip requires VM information")
			retval={}
		elif retval['cmd'] == 'get_ip' and len(argv)==3:
			retval['vm'] = argv[2]
	return retval

def checking_config_syntax(d1):
	retval=1
	# checking type and os
	for i in d1['vm'].keys():
		# checking vm type
		if not d1['vm'][i]['type'] in param1.vm_type:
			print("ERROR for VM ",i)
			print("this type of VM, " + d1['vm'][i]['type'] + " is not supported yet")
			return 0
		if not d1['vm'][i]['os'] in param1.vm_os:
			print("ERROR for VM ",i)
			print("this OS " + d1['vm'][i]['os'] + " is not supported yet")
			return 0
	# checking interface
	for i in d1['vm'].keys():
		if (d1['vm'][i]['type'] in param1.vm_type.keys()) and (d1['vm'][i]['type']!='junos'):
			for j in d1['vm'][i]['interfaces'].keys():
				if 'em' not in j:
					print("ERROR for VM ",i)
					print("interface " + j + " is not supported")
					return 0
			for j in d1['vm'][i]['interfaces'].keys():
				if list(d1['vm'][i]['interfaces'].keys()).count(j) > 1:
					print("ERROR for VM ",i)
					print("duplicate interfaces " + j + " is found")
					return 0
	return retval

def get_ip(d1,vm):
	print("VM %s %s " %(vm,get_ip_vm(d1,vm)))
	# write_ssh_config(d1)

def get_vga(d1):
	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	# ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'],password=d1['vmm_pod']['password'])
	ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'])
	print('-----')
	print("vga port of VM (on VNC, please add 5900 for the port")
	cmd1="vmm list"
	s1,s2,s3=ssh.exec_command(cmd1)
	vm_list=[]
	for i in s2.readlines():
		vm_list.append(i.rstrip().split()[0])	
	for i in vm_list:
		cmd1="vmm args " + i + " | grep \"vga_display \""
		s1,s2,s3=ssh.exec_command(cmd1)
		for j in s2.readlines():
			print("VGA port of " + i + " : " + j.rstrip().split()[1])

def get_ip_vm(d1,i):
	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	# ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'],password=d1['vmm_pod']['password'])
	ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'])
	# print('-----')
	# print("serial port of VM")
	# cmd1="vmm list"
	# s1,s2,s3=ssh.exec_command(cmd1)
	#vm_list=[]
	#for i in s2.readlines():
	#	vm_list.append(i.rstrip().split()[0])	
	# for i in vm_list:
	cmd1="vmm args " + i + " | grep \"ip_addresses \""
	# print("command ", cmd1)
	stdin,stdout,sstderr=ssh.exec_command(cmd1)
	# print("output ", stdout.readlines())
	j = stdout.readlines()
	# print("j : ",j)
	list1= j[0].rstrip().split()
	if len(list1)==2:
		retval = list1[1]
	else:
		retval = "No External IP"
	# if j:
	#	retval = j[0].rstrip().split()[1]
	#else:
	# print("ip ",j[0].rstrip().split()[1].lstrip())

	return retval
	#	for j in s2.readlines():
	#		print("serial of " + i + " : " + j.rstrip().split()[1])

def get_serial(d1):
	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	# ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'],password=d1['vmm_pod']['password'])
	ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'])
	print('-----')
	print("serial port of VM")
	cmd1="vmm list"
	s1,s2,s3=ssh.exec_command(cmd1)
	# ssh.close()
	vm_list=[]
	for i in s2.readlines():
		vm_list.append(i.rstrip().split()[0])	
	print("vm list", vm_list)
	for i in vm_list:
		print("serial of " + i + " : " + get_serial_vm(d1,i))


def get_serial_vm(d1,i):
	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'])
	cmd1="vmm args " + i + " | grep \"serial \""
	s1,s2,s3=ssh.exec_command(cmd1)
	j=s2.readlines()[0]
	# print("s2.readlines ",j)
	# for j in s2.readlines():
	# return '0'
	return j.rstrip().split()[1]

def list_vm(d1):
	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	# ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'],password=d1['vmm_pod']['password'])
	ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'])
	print('-----')
	cmd1="vmm list"
	s1,s2,s3=ssh.exec_command(cmd1)
	for i in s2.readlines():
		print(i.rstrip())

def stop(d1):
	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	# ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'],password=d1['vmm_pod']['password'])
	ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'])
	print('-----')
	print("stop the existing topology")
	cmd1="vmm stop"
	s1,s2,s3=ssh.exec_command(cmd1)
	for i in s2.readlines():
		print(i.rstrip())

def start(d1):
	lab_conf=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/lab.conf"
	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	# ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'],password=d1['vmm_pod']['password'])
	ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'])
	print('-----')
	print("stop and unbind the existing topology")
	cmd1="vmm stop"
	s1,s2,s3=ssh.exec_command(cmd1)
	for i in s2.readlines():
		print(i.rstrip())
	cmd1="vmm unbind"
	s1,s2,s3=ssh.exec_command(cmd1)
	for i in s2.readlines():
		print(i.rstrip())
	print("start configuration ")
	cmd1="vmm config " + lab_conf  + " " + param1.vmm_group
	s1,s2,s3=ssh.exec_command(cmd1)
	for i in s2.readlines():
		print(i.rstrip())
	print("start topology ")
	cmd1="vmm start"
	s1,s2,s3=ssh.exec_command(cmd1)
	for i in s2.readlines():
		print(i.rstrip())
	write_ssh_config(d1)
	check_ubuntu1804(d1)

def upload(d1):
# creating lab.conf
	if not checking_config_syntax(d1):
		return
	# print("still continue")
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	home_dir=param1.home_dir + d1['vmm_pod']['user'] + "/"
	lab_conf=[]
	lab_conf.append('#include "/vmm/bin/common.defs"')
	lab_conf.append('#include "/vmm/data/user_disks/vmxc/common.vmx.p3.defs"')
	vm_os_d1=[]
	for i in d1['vm'].keys():
		# print(i,d1['vm'][i]['os'])
		if 'disk' in d1['vm'][i].keys():
			temp_s1=d1['vm'][i]['os'] + "_" + d1['vm'][i]['disk']	
		else:
			temp_s1=d1['vm'][i]['os']
		if temp_s1 not in vm_os_d1:
			vm_os_d1.append(temp_s1)
	# print("vm_os_d1 ",vm_os_d1)
	for i in vm_os_d1:
		if i=='vmx' or i=='mx960' or i=='mx480' or i=='mx240':
			str1="#undef VMX_DISK0"
			lab_conf.append(str1)
			str1='#define VMX_DISK0  basedisk "' + home_dir + d1['vmm_pod']['image']['vmx_re'] + '";'
			lab_conf.append(str1)
			str1="#undef VMX_DISK1"
			lab_conf.append(str1)
			str1='#define VMX_DISK1  basedisk "' + home_dir + d1['vmm_pod']['image']['vmx_mpc'] + '";'
			lab_conf.append(str1)
		elif i=='vqfx':
			str1="#undef VQFX_RE"
			lab_conf.append(str1)
			str1='#define VQFX_RE  basedisk "' + home_dir + d1['vmm_pod']['image']['vqfx_re'] + '";'
			lab_conf.append(str1)
			str1="#undef VQFX_COSIM"
			lab_conf.append(str1)
			str1='#define VQFX_COSIM  basedisk "' + home_dir + d1['vmm_pod']['image']['vqfx_cosim'] + '";'
			lab_conf.append(str1)
		elif i=='vsrx':
			str1="#undef VSRXDISK"
			lab_conf.append(str1)
			str1='#define VSRXDISK basedisk "' + home_dir + d1['vmm_pod']['image']['vsrx'] + '";'
			lab_conf.append(str1)
		else:
			temp_s1=i.upper() + "_DISK"
			str1="#undef " + temp_s1
			lab_conf.append(str1)
			str1='#define ' + temp_s1 + ' basedisk "' + home_dir + d1['vmm_pod']['image'][i] + '";'
			lab_conf.append(str1)
				
# 		elif i=='centos':
# 			str1='#define CENTOSDISK  basedisk "' + home_dir + d1['vmm_pod']['image']['centos'] + '";'
# 			lab_conf.append(str1)
# 		elif i=='centosx':
# 			str1='#define CENTOSXDISK  basedisk "' + home_dir + d1['vmm_pod']['image']['centosx'] + '";'
# 			lab_conf.append(str1)
# 		elif i=='ubuntu':
# 			str1='#define UBUNTUDISK basedisk "' + home_dir + d1['vmm_pod']['image']['ubuntu'] + '";'
# 			lab_conf.append(str1)
# 		elif i=='ubuntu1804':
# 			str1='#define UBUNTU1804DISK basedisk "' + home_dir + d1['vmm_pod']['image']['ubuntu1804'] + '";'
# 			lab_conf.append(str1)
		# print("everything is ok")
	str1='config "' +d1['name'] + '"{'
	lab_conf.append(str1)
	lab_conf.extend(list_bridge(d1))
	# bridge1=list_bridge(d1)
	# print("Bridge ",bridge1)

# creating VM configuration
	for i in d1['vm'].keys():
		if d1['vm'][i]['type'] == 'gw':
			lab_conf.extend(make_gw_config(d1,i))
		elif d1['vm'][i]['type'] in param1.pc_type:
			lab_conf.extend(make_pc_config(d1,i))
		elif d1['vm'][i]['type'] == 'junos':
			lab_conf.extend(make_junos_config(d1,i))
	lab_conf.append('};')

	if os.path.exists(param1.tmp_dir):
		print("directory exist ")
		shutil.rmtree(param1.tmp_dir)
	os.mkdir(param1.tmp_dir)
	f1=param1.tmp_dir + "lab.conf"
	write_to_file(f1,lab_conf)
	# write_to_file(param1.tmp_dir + "lab.conf",lab_conf)
	write_pc_config_to_file(d1)
	# f1=param1.tmp_dir + "resolv.conf"
	# write_to_file(f1,["nameserver 10.49.0.4","nameserver 10.49.0.37"])
	f1=param1.tmp_dir + "01-ip_forward.conf"
	line1=["net.ipv4.ip_forward=1"]
	write_to_file(f1,line1)
	# write_to_file(param1.tmp_dir + "01-ip_forward.conf",line1)
	f1=param1.tmp_dir + "rc.local.gw"
	line1=["#!/bin/bash","touch /var/lock/subsys/local","systemctl stop firewalld","systemctl disable firewalld","chown centos:centos /home/centos/.ssh/authorized_keys","chmod 0600 /home/centos/.ssh/authorized_keys","iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE","echo \"#!/bin/bash\" > /tmp/rc.local","echo \"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\" >> /tmp/rc.local","echo \"touch /var/lock/subsys/local\" >> /tmp/rc.local","cat /tmp/rc.local > /etc/rc.d/rc.local","rm -f /tmp/rc.local","chmod +x /etc/rc.d/rc.local"]
	write_to_file(f1,line1)
	# write_to_file(param1.tmp_dir + "rc.local.gw",line1)
	f1=param1.tmp_dir + "rc.local.ubuntu"
	line1=["#!/bin/bash","touch /var/lock/subsys/local","systemctl stop firewalld","systemctl disable firewalld","chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys","chmod 0600 /home/ubuntu/.ssh/authorized_keys","echo \"#!/bin/bash\" > /tmp/rc.local","echo \"touch /var/lock/subsys/local\" >> /tmp/rc.local","cat /tmp/rc.local > /etc/rc.d/rc.local","rm -f /tmp/rc.local","chmod +x /etc/rc.d/rc.local"]
	write_to_file(f1,line1)
	f1=param1.tmp_dir + "rc.local.centos"
	line1=["#!/bin/bash","touch /var/lock/subsys/local","systemctl stop firewalld","systemctl disable firewalld","chown centos:centos /home/centos/.ssh/authorized_keys","chmod 0600 /home/centos/.ssh/authorized_keys","echo \"#!/bin/bash\" > /tmp/rc.local","echo \"touch /var/lock/subsys/local\" >> /tmp/rc.local","cat /tmp/rc.local > /etc/rc.d/rc.local","rm -f /tmp/rc.local","chmod +x /etc/rc.d/rc.local"]
	write_to_file(f1,line1)
	# write_to_file(param1.tmp_dir + "rc.local",line1)
	write_junos_config(d1)
	write_ssh_key(d1)
	write_inventory(d1)
	upload_file_to_server(d1)

def write_inventory(d1):
	print("writing inventory for ansible")
	f1=param1.tmp_dir + "inventory"
	line1=["[all]"]
	for i in d1['vm'].keys():
		if d1['vm'][i]['type'] == 'junos':
			line1.append(i)
	line1.append("[all:vars]")
	line1.append("ansible_python_interpreter=/usr/bin/python")
	write_to_file(f1,line1)

def write_ssh_key(d1):
	print("writing ssh_key")
	f1=param1.tmp_dir + "ssh_key"
	line1=[d1['vmm_pod']['junos_login']['ssh_key']]
	write_to_file(f1,line1)

def write_ssh_config(d1):
	file1=[]
	print("writing file ssh_config")
	for i in d1['vm'].keys():
		if d1['vm'][i]['type']=='gw':
			gw_name = i
	file1.append("""Host *
    StrictHostKeyChecking no
	
	""")
	for i in d1['vm'].keys():
		if d1['vm'][i]['type']=='gw':
			file1.append("host %s" %(i))
			file1.append("   hostname %s" %(get_ip_vm(d1,i)))
			file1.append(get_ssh_user(d1,i))
			file1.append("   IdentityFile ~/.ssh/id_rsa")
			file1.append("   ")
			file1.append("host %s" %('proxy'))
			file1.append("   hostname %s" %(get_ip_vm(d1,i)))
			file1.append(get_ssh_user(d1,i))
			file1.append("   IdentityFile ~/.ssh/id_rsa")
			file1.append("   DynamicForward 1080")
		else:
			file1.append("host %s" %(i))
			file1.append(get_ssh_user(d1,i))
			file1.append("   IdentityFile ~/.ssh/id_rsa")
			file1.append("   ProxyCommand ssh -W %s:22 %s " %(get_ip_mgmt(d1,i),gw_name))
	print("write ssh_config")
	f1=param1.tmp_dir + "ssh_config"
	write_to_file(f1,file1)
	# for i in file1:
	#	print(i)
				
def get_ip_mgmt(d1,i):
	retval=""	
	if d1['vm'][i]['type'] != 'gw':
		for j in d1['vm'][i]['interfaces'].keys():
			if j == 'em0' or j=='fxp0':
			# if d1['vm'][i]['interfaces'][j]['bridge']=='mgmt':
				retval = d1['vm'][i]['interfaces'][j]['ipv4'].split("/")[0]
	return retval

def get_ssh_user(d1,i):
	if d1['vm'][i]['type'] == 'junos':
		retval="   user admin"
	else:
		# if d1['vm'][i]['os'] == 'centos' or d1['vm'][i]['os'] == 'centosx':
		if 'centos' in d1['vm'][i]['os']:
			retval="   user centos"
		# elif d1['vm'][i]['os'] == 'ubuntu' or d1['vm'][i]['os'] == 'ubuntu1804':
		elif 'ubuntu' in d1['vm'][i]['os']:
			retval="   user ubuntu"
	return retval


def upload_file_to_server(d1):
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	home_dir=param1.home_dir + d1['vmm_pod']['user'] + "/"
	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	# ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'],password=d1['vmm_pod']['password'])
	ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'])
	cmd1="rm -rf " + config_dir
	print("deleting config_dir")
	s1,s2,s3=ssh.exec_command(cmd1)
	cmd1="mkdir " + config_dir
	print("creating config_dir")
	s1,s2,s3=ssh.exec_command(cmd1)
	file1=os.listdir("./tmp")
	print("current directory ",file1)
	sftp=ssh.open_sftp()
	for i in file1: 
		print("upload file ./tmp/" + i + " to " + config_dir)
		sftp.put("./tmp/" + i,config_dir + i)
	sftp.close()

def write_junos_config(d1):
	for i in d1['vm'].keys():
		if d1['vm'][i]['type'] == 'junos':
			if d1['vm'][i]['os'] == 'vmx' or d1['vm'][i]['os'] == 'mx960' or d1['vm'][i]['os'] == 'mx480' or d1['vm'][i]['os'] == 'mx240':
				write_vmx_config(d1,i)
			elif d1['vm'][i]['os'] == 'vqfx':
				write_vqfx_config(d1,i)
			elif d1['vm'][i]['os'] == 'vsrx':
				write_vsrx_config(d1,i)
				
def write_vmx_config(d1,i):
	print("creating vmx config ",i)
	line1=[]
	line1.append("groups {")
	line1.append("  base_config {")
	line1.append("system {")
	line1.append("   host-name " + i + ";")
	line1.append("   root-authentication {")
	line1.append("      encrypted-password \"" +  md5_crypt.hash(d1['vmm_pod']['junos_login']['password'])+ "\";")
	line1.append("   }")
	line1.append("   login {")
	line1.append("      user " + d1['vmm_pod']['junos_login']['login']+ " {")
	line1.append("         class super-user;")
	line1.append("         authentication {")
	line1.append("            encrypted-password \"" + md5_crypt.hash(d1['vmm_pod']['junos_login']['password']) + "\";")
	if 'ssh_key' in d1['vmm_pod']['junos_login'].keys():
		line1.append("            ssh-rsa \"" + d1['vmm_pod']['junos_login']['ssh_key'] + "\";")
	line1.append("         }")
	line1.append("      }")
	line1.append("   }")
	line1.append("""   services {
        ssh;
        netconf {
            ssh;
        }
    }
    syslog {
        user * {
            any emergency;
        }
        file messages {
            any notice;
            authorization info;
        }
        file interactive-commands {
            interactive-commands any;
        }
    }
}
chassis {
   network-services enhanced-ip;
}""")
	line1.append("""interfaces {
   fxp0 {
      unit 0 {
         family inet {
             address %s;
         }
      }
    }
}
}
}""" % (d1['vm'][i]['interfaces']['fxp0']['ipv4']) )
	line1.append("apply-groups base_config;")
	f1=param1.tmp_dir + i + ".conf"
	write_to_file(f1,line1)
	# write_to_file(param1.tmp_dir + i + ".conf",line1)

def write_vqfx_config(d1,i):
	print("creating vqfx config ",i)
	line1=[]
	line1.append("groups {")
	line1.append("  base_config {")
	line1.append("system {")
	line1.append("   host-name " + i + ";")
	line1.append("   root-authentication {")
	line1.append("      encrypted-password \"" +  md5_crypt.hash(d1['vmm_pod']['junos_login']['password'])+ "\";")
	line1.append("   }")
	line1.append("   login {")
	line1.append("      user " + d1['vmm_pod']['junos_login']['login']+ " {")
	line1.append("         class super-user;")
	line1.append("         authentication {")
	line1.append("            encrypted-password \"" + md5_crypt.hash(d1['vmm_pod']['junos_login']['password']) + "\";")
	if 'ssh_key' in d1['vmm_pod']['junos_login'].keys():
		line1.append("            ssh-rsa \"" + d1['vmm_pod']['junos_login']['ssh_key'] + "\";")
	line1.append("         }")
	line1.append("      }")
	line1.append("   }")
	line1.append("""   services {
        ssh;
        netconf {
            ssh;
        }
    }
    syslog {
        user * {
            any emergency;
        }
        file messages {
            any notice;
            authorization info;
        }
        file interactive-commands {
            interactive-commands any;
        }
    }
    extensions {
       providers {
           juniper {
              license-type juniper deployment-scope commercial;
           }
           chef {
              license-type juniper deployment-scope commercial;
           }
       }
   }
}
""")
	line1.append("""interfaces {
   em0 {
      unit 0 {
         family inet {
             address %s;
         }
      }
    }
}""" % (d1['vm'][i]['interfaces']['em0']['ipv4']) )
	line1.append("""interfaces {
   em1 {
     unit 0 {
        family inet {
           address 169.254.0.2/24;
        }
     }
   }
}
forwarding-options {
   storm-control-profiles default {
      all;
   }
}
protocols {
   igmp-snooping {
       vlan default;
   }
}
vlans {
  default {
     vlan-id 1;
  }
}
}
}""")
	line1.append("apply-groups base_config;")
	f1=param1.tmp_dir + i + ".conf"
	write_to_file(f1,line1)
	# write_to_file(param1.tmp_dir + i + ".conf",line1)


def write_vsrx_config(d1,i):
	print("creating vsrx config ",i)
	line1=[]
	line1.append("groups {")
	line1.append("  base_config {")
	line1.append("system {")
	line1.append("   host-name " + i + ";")
	line1.append("   root-authentication {")
	line1.append("      encrypted-password \"" +  md5_crypt.hash(d1['vmm_pod']['junos_login']['password'])+ "\";")
	line1.append("   }")
	line1.append("   login {")
	line1.append("      user " + d1['vmm_pod']['junos_login']['login']+ " {")
	line1.append("         class super-user;")
	line1.append("         authentication {")
	line1.append("            encrypted-password \"" + md5_crypt.hash(d1['vmm_pod']['junos_login']['password']) + "\";")
	if 'ssh_key' in d1['vmm_pod']['junos_login'].keys():
		line1.append("            ssh-rsa \"" + d1['vmm_pod']['junos_login']['ssh_key'] + "\";")
	line1.append("         }")
	line1.append("      }")
	line1.append("   }")
	line1.append("""   services {
        ssh;
        netconf {
            ssh;
        }
				web-management {
            http {
                interface fxp0.0;
            }
            https {
                system-generated-certificate;
                interface fxp0.0;
            }
        }
    }
    syslog {
        user * {
            any emergency;
        }
        file messages {
            any notice;
            authorization info;
        }
        file interactive-commands {
            interactive-commands any;
        }
    }
}
""")
	line1.append("""interfaces {
   fxp0 {
      unit 0 {
         family inet {
             address %s;
         }
      }
    }
}""" % (d1['vm'][i]['interfaces']['fxp0']['ipv4']) )
	line1.append("""security {
		screen {
        ids-option untrust-screen {
            icmp {
                ping-death;
            }
            ip {
                source-route-option;
                tear-drop;
            }
            tcp {
                syn-flood {
                    alarm-threshold 1024;
                    attack-threshold 200;
                    source-threshold 1024;
                    destination-threshold 2048;
                    timeout 20;
                }
                land;
            }
        }
    }
		policies {
				from-zone trust to-zone trust {
            policy default-permit {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
				from-zone trust to-zone untrust {
            policy default-permit {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
		}
		zones {
			security-zone trust {
            tcp-rst;
        }
      security-zone untrust {
            screen untrust-screen;
        }
		}
	}
	}
	}""")
	line1.append("apply-groups base_config;")
	f1=param1.tmp_dir + i + ".conf"
	write_to_file(f1,line1)
	# write_to_file(param1.tmp_dir + i + ".conf",line1)


def write_pc_config_to_file(d1):
	print("writing pc conf")
	hosts_file=['127.0.0.1	localhost.localdomain localhost','::1		localhost6.localdomain6 localhost6']
	for i in d1['vm'].keys():
		if d1['vm'][i]['type'] != 'junos':
			f1=param1.tmp_dir + "hostname." + i
			print("write_pc_config_to_file ", i)
			write_to_file(f1,[i])
	for i in d1['vm'].keys():
		if d1['vm'][i]['type'] != 'junos':
			if 'centos' in d1['vm'][i]['os']:
				for j in d1['vm'][i]['interfaces']:
					line1=[]
					if 'ipv4' in d1['vm'][i]['interfaces'][j].keys():
						intf=j.replace('em','eth')
						f1=param1.tmp_dir + "ifcfg-" + intf + "." + i
						line1.append('NAME=' + intf)
						line1.append('DEVICE='+intf)
						line1.extend(['TYPE=Ethernet','BOOTPROTO=static','ONBOOT=yes'])
						line1.append('IPADDR=' + d1['vm'][i]['interfaces'][j]['ipv4'].split('/')[0])
						line1.append('NETMASK=' + prefix2netmask(d1['vm'][i]['interfaces'][j]['ipv4'].split('/')[1]))
						if 'mtu' in d1['vm'][i]['interfaces'][j].keys():
							line1.append('MTU=' + str(d1['vm'][i]['interfaces'][j]['mtu']))
						if 'gateway4' in d1['vm'][i]['interfaces'][j].keys():
							line1.append('GATEWAY=' + d1['vm'][i]['interfaces'][j]['gateway4'])
							if 'dns' in d1['vm'][i]['interfaces'][j].keys():
								line1.append('DNS1=' + d1['vm'][i]['interfaces'][j]['dns'])
							hosts_file.append(d1['vm'][i]['interfaces'][j]['ipv4'].split('/')[0] + ' ' + i)
						f1=param1.tmp_dir + "ifcfg-" + intf + "." + i
					else:
						intf=j.replace('em','eth')
						f1=param1.tmp_dir + "ifcfg-" + intf + "." + i
						line1.append('NAME=' + intf)
						line1.append('DEVICE='+intf)
						line1.extend(['TYPE=Ethernet','BOOTPROTO=manual','ONBOOT=yes'])
						if 'mtu' in d1['vm'][i]['interfaces'][j].keys():
							line1.append('MTU=' + str(d1['vm'][i]['interfaces'][j]['mtu']))
					write_to_file(f1,line1)
			elif d1['vm'][i]['os']=='ubuntu':
				line1=[]
				line1.append("auto lo")
				line1.append("iface lo inet loopback")
				for j in d1['vm'][i]['interfaces']:
					if 'ipv4' in d1['vm'][i]['interfaces'][j].keys():
						intf=j.replace('em','eth')
						line1.append("auto " + intf)
						line1.append("iface " + intf + " inet static")
						line1.append("    address " + d1['vm'][i]['interfaces'][j]['ipv4'].split('/')[0])
						line1.append("    netmask " + prefix2netmask(d1['vm'][i]['interfaces'][j]['ipv4'].split('/')[1]))
						if 'mtu' in d1['vm'][i]['interfaces'][j].keys():
							line1.append('	  mtu ' + str(d1['vm'][i]['interfaces'][j]['mtu']))
						if 'gateway4' in d1['vm'][i]['interfaces'][j].keys():
							line1.append('   gateway ' + d1['vm'][i]['interfaces'][j]['gateway4'])
							if 'dns' in d1['vm'][i]['interfaces'][j].keys():
								line1.append('   dns-nameservers ' + d1['vm'][i]['interfaces'][j]['dns'])
							hosts_file.append(d1['vm'][i]['interfaces'][j]['ipv4'].split('/')[0] + ' ' + i)
					else:
						intf=j.replace('em','eth')
						line1.append("auto " + intf)
						line1.append("iface " + intf + " inet manual")
						if 'mtu' in d1['vm'][i]['interfaces'][j].keys():
							line1.append('	  mtu ' + str(d1['vm'][i]['interfaces'][j]['mtu']))
				f1=param1.tmp_dir + "interfaces." + i
				write_to_file(f1,line1)
			elif d1['vm'][i]['os']=='ubuntu1804':
				line1=[]
				line1.append("network:")
				line1.append("  ethernets:")
				for j in d1['vm'][i]['interfaces']:
					if 'ipv4' in d1['vm'][i]['interfaces'][j].keys():
						intf=j.replace('em','eth')
						line1.append("    " + intf + ":")
						line1.append("      addresses:")
						line1.append("        - "+ d1['vm'][i]['interfaces'][j]['ipv4'])
						if 'mtu' in d1['vm'][i]['interfaces'][j].keys():
							line1.append('      mtu : ' + str(d1['vm'][i]['interfaces'][j]['mtu']))
						if 'gateway4' in d1['vm'][i]['interfaces'][j].keys():
							line1.append('      gateway4: ' + d1['vm'][i]['interfaces'][j]['gateway4'])
							if 'dns' in d1['vm'][i]['interfaces'][j].keys():
								line1.append('      nameservers:')
								line1.append('        addresses:')
								line1.append('           - ' + d1['vm'][i]['interfaces'][j]['dns'])
							hosts_file.append(d1['vm'][i]['interfaces'][j]['ipv4'].split('/')[0] + ' ' + i)
					else:
						intf=j.replace('em','eth')
						line1.append("    " + intf + ":")
						line1.append("       dhcp4: no")
						if 'mtu' in d1['vm'][i]['interfaces'][j].keys():
							line1.append('       mtu : ' + str(d1['vm'][i]['interfaces'][j]['mtu']))
				f1=param1.tmp_dir + "interfaces." + i
				write_to_file(f1,line1)
	write_to_file(param1.tmp_dir + "hosts",hosts_file)

def prefix2netmask(prefs):
	i=0
	b=[]
	pref = int(prefs)
	for i in range(4):
		# print("pref ",pref)
		if pref >= 8:
			b.append(255)
		elif pref >= 0:
			b1=0
			f1=7
			for j in list(range(pref)):
				b1 +=  2 ** f1
				f1 -= 1
			b.append(b1)
		else:
			b.append(0)
		pref -= 8
	return str(b[0]) + "." + str(b[1]) + "." + str(b[2]) + "." + str(b[3])

def write_to_file(f1,line1):
	print("writing " + f1)
	try:
		of=open(f1,"w")
		for i in line1:
			of.write(i + "\n")
		of.close()
	except PermissionError:
		print("permission error")

def list_bridge(d1):
	vm_list=list(d1['vm'].keys())
	retval=[]
	bridge1=[]
	for i in vm_list:
		for j in d1['vm'][i]['interfaces'].keys():
			if d1['vm'][i]['interfaces'][j]['bridge'] != 'external':
				if d1['vm'][i]['interfaces'][j]['bridge'] not in bridge1:
					bridge1.append(d1['vm'][i]['interfaces'][j]['bridge'])
	for i in bridge1:
		retval.append('  bridge "' + i + '"{};')
	retval.append('  bridge "reserved_bridge" {};')
	for i in d1['vm'].keys():
		if d1['vm'][i]['os']=='vqfx':
			retval.append('  bridge "' + i + 'INT"{};')
	retval.append('  PRIVATE_BRIDGES')
	return retval

def get_bridge_name(intf):
	if isinstance(intf,list):
		return intf[0]
	elif isinstance(intf,str):
		return intf

def change_intf(intf):
	return intf.replace('em','eth')
# def change_intfx(intf):
#	return intf.replace('em','ens3f')

def make_config_generic_pc(d1,i):
	retval=[]
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	# print("Make config for GW for vm ",i)
	retval.append('vm "'+i+'" {')
	retval.append('   hostname "'+i+'";')
	if 'disk' in d1['vm'][i].keys():
		temp_s1="    " + d1['vm'][i]['os'].upper() + "_" + d1['vm'][i]['disk'].upper() +  "_DISK"
	else:
		temp_s1="    " + d1['vm'][i]['os'].upper() +  "_DISK"
	retval.append(temp_s1)

# 	if d1['vm'][i]['os']=='centos':
# 		retval.append('   CENTOSDISK')
# 	elif d1['vm'][i]['os']=='centosx':
# 		retval.append('   CENTOSXDISK')
# 	elif d1['vm'][i]['os']=='ubuntu':
# 		retval.append('   UBUNTUDISK')
# 	elif d1['vm'][i]['os']=='ubuntu1804':
# 		retval.append('   UBUNTU1804DISK')
	# print("PC Name :",i)
	# print("PC type :",d1['vm'][i]['type'])
	
	retval.append('   setvar "+qemu_args" "-cpu qemu64,+vmx";')
	retval.append('   ncpus ' + str(param1.vm_type[d1['vm'][i]['type']]['ncpus']) + ';')
	retval.append('   memory ' + str(param1.vm_type[d1['vm'][i]['type']]['memory']) + ';')
	for j in d1['vm'][i]['interfaces'].keys():
		retval.append('   interface "' +  j + '" { bridge "' + d1['vm'][i]['interfaces'][j]['bridge'] + '";};')
	retval.append('   install "' + config_dir + "hostname." + i + '" "/etc/hostname";')
	
	# if d1['vm'][i]['os'] == 'centos' or d1['vm'][i]['os'] == 'centosx':
	# if 'centos' in d1['vm'][i]['os']:

	if d1['vm'][i]['os'] == 'centos':
		retval.append('   install "' + config_dir + "hosts" + '" "/etc/hosts";')
		for j in d1['vm'][i]['interfaces'].keys():
			if 'ipv4' in d1['vm'][i]['interfaces'][j]:
				retval.append('   install "' + config_dir + "ifcfg-" + change_intf(j) + '.' + i + '" "/etc/sysconfig/network-scripts/ifcfg-' + change_intf(j) +  '";')
	elif d1['vm'][i]['os'] == 'ubuntu':
		retval.append('   install "' + config_dir + "hosts" + '" "/etc/hosts";')
		retval.append('   install "' + config_dir + "interfaces." + i + '" "/etc/network/interfaces";')
	elif d1['vm'][i]['os'] == 'ubuntu1804':
		retval.append('   install "' + config_dir + "hosts" + '" "/etc/hosts";')
		retval.append('   install "' + config_dir + "interfaces." + i + '" "/etc/netplan/50-cloud-init.yaml";')

	return retval

def make_gw_config(d1,i):
	retval=[]
	# config_dir=param1.home_dir + d1['name'] + "/"
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	retval.extend(make_config_generic_pc(d1,i))
	retval.append('   install "' + config_dir + 'ssh_key" "/home/centos/.ssh/authorized_keys";' )
	retval.append('   install "' + config_dir + '01-ip_forward.conf" "/etc/sysctl.d/01-ip_forward.conf";' )
	retval.append('   install "' + config_dir + 'rc.local.gw" "/etc/rc.d/rc.local";' )
	retval.append('};')
	return retval

def make_pc_config(d1,i):
	retval=[]
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	retval.extend(make_config_generic_pc(d1,i))
	if d1['vm'][i]['os'] == 'centos':
		retval.append('   install "' + config_dir + 'rc.local.centos" "/etc/rc.d/rc.local";' )
	
		retval.append('   install "' + config_dir + 'ssh_key" "/home/centos/.ssh/authorized_keys";' )
	
	if 'ubuntu' in d1['vm'][i]['os']:
		retval.append('   install "' + config_dir + 'rc.local.ubuntu" "/etc/rc.d/rc.local";' )
		retval.append('   install "' + config_dir + 'ssh_key" "/home/ubuntu/.ssh/authorized_keys";' )

	# retval.append('   install "' + config_dir + 'resolv.conf" "/etc/resolv.conf";' )
	retval.append('};')
	return retval

def make_junos_config(d1,i):
	retval=[]
	# print("Make config for Junos for vm ",i)
	if d1['vm'][i]['os']=='vmx' or d1['vm'][i]['os']=='mx960' or d1['vm'][i]['os']=='mx480' or d1['vm'][i]['os']=='mx240':
		retval=make_vmx_config(d1,i)
	elif d1['vm'][i]['os']=='vqfx':
		retval=make_vqfx_config(d1,i)
	elif d1['vm'][i]['os']=='vsrx':
		 retval=make_vsrx_config(d1,i)
	return retval

def vmx_get_intf(d1,i):
	retval=[]
	intf = d1['vm'][i]['interfaces']
	for j in intf.keys():
		if 'ge' in j:
			retval.append("            VMX_CONNECT(GE("+ j.split('-')[1].replace('/',',') + "), " + d1['vm'][i]['interfaces'][j]['bridge'] + ")")
	return retval

def make_vmx_config(d1,i):
	retval=[]
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	# print("make config for VMX ",i)
	# getting the management interface bridge
	# fxp=d1['vm'][i]['interfaces']['fxp0']
	# if 'ipv4' no in not isinstance(fxp,list):
	if 'ipv4' not in d1['vm'][i]['interfaces']['fxp0'].keys():
		print("where is the ip address ? ")
		exit
	else:
		# ip_mgmt=d1['vm'][i]['interfaces']['fxp0'][1]
		retval.append("   ")
		retval.append("   #undef EM_IPADDR")
		retval.append("   #define EM_IPADDR interface \"em0\" { bridge \"" + d1['vm'][i]['interfaces']['fxp0']['bridge'] + "\";};")
		if d1['vm'][i]['os'] == 'vmx': 
			retval.append("   #define VMX_CHASSIS_I2CID 161")
		elif d1['vm'][i]['os'] == 'mx960': 
			retval.append("   #define VMX_CHASSIS_I2CID 21")
		elif d1['vm'][i]['os'] == 'mx480': 
			retval.append("   #define VMX_CHASSIS_I2CID 33")
		elif d1['vm'][i]['os'] == 'mx240': 
			retval.append("   #define VMX_CHASSIS_I2CID 48")
		retval.append("   #define VMX_CHASSIS_NAME " + i)
		retval.append("   VMX_CHASSIS_START() ")
		retval.append("      VMX_RE_START("+i+"_re,0)")
		retval.append("         VMX_RE_INSTANCE("+i+"_re0, VMX_DISK0, VMX_RE_I2CID,0)")
		retval.append("         install \"" + config_dir + i + ".conf\" \"/root/junos.base.conf\";")
		retval.append("      VMX_RE_END");
		retval.append("      VMX_MPC_START("+i+"_MP,0)")
		retval.append("        VMX_MPC_INSTANCE("+i+"_MPC, VMX_DISK1, VMX_MPC_I2CID, 0)")
		retval.extend(vmx_get_intf(d1,i))
		retval.append("      VMX_MPC_END");
		retval.append("   VMX_CHASSIS_END");
		retval.append("   #undef VMX_CHASSIS_I2CID")
		retval.append("   #undef VMX_CHASSIS_NAME")
	return retval

def make_vqfx_config(d1,i):
	# creating config for RE of VQFX
	retval=[]
	# print("make config for VQFX ",i)
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	retval.append('')
	retval.append('   vm "'+i +'_re" {')
	retval.append('      hostname "'+i+'_re";')
	retval.append('      VQFX_RE')
	retval.append('      setvar "boot_noveriexec" "YES";')
	retval.append('      setvar "qemu_args" "-smbios type=1,product=QFX10K-11";')
	retval.append("      install \"" + config_dir + i + ".conf\" \"/root/junos.base.conf\";")
	# mgmt_bridge=get_bridge_name(d1['vm'][i]['interfaces']['em0'])
	mgmt_bridge=d1['vm'][i]['interfaces']['em0']['bridge']
	retval.append('      interface "em0" { bridge "' + mgmt_bridge + '"; };')
	retval.append('      interface "em1" { bridge "' + i + "INT" + '"; ipaddr "169.254.0.2"; };')
	retval.append('      interface "em2" { bridge "reserved_bridge"; };')
	intf_list=[]
	for j in d1['vm'][i]['interfaces'].keys():
		if j != "em0":
			intf_list.append(j)	
	intf_list.sort()
	for j in intf_list:
		intf_name = "em" + str(int(j.split("/")[2]) + 3)
		retval.append('      interface "' +  intf_name + '" { bridge "' + d1['vm'][i]['interfaces'][j]['bridge'] + '";};')
	retval.append('   };')

	# creating config for COSIM of VQFX
	retval.append('   vm "'+i +'_cosim" {')
	retval.append('      hostname "'+i+'_cosim";')
	retval.append('      VQFX_COSIM')
	retval.append('      memory 4096;')
	retval.append('      ncpus 2;')
	retval.append('      interface "em0" { bridge "' + mgmt_bridge + '"; };')
	retval.append('      interface "em1" { bridge "' + i + "INT" + '"; ipaddr "169.254.0.1"; };')
	retval.append('   };')
	retval.append('')
	return retval

def make_vsrx_config(d1,i):
	retval=[]
	mgmt_bridge=d1['vm'][i]['interfaces']['fxp0']['bridge']
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	intf_list=[]
	print("make config for srx ",i)
	retval.append('vm "'+i+'" {')
	retval.append('   hostname "'+i+'";')
	retval.append('      VSRXDISK')
	retval.append('      memory 4096;')
	retval.append('      ncpus 2;')
	retval.append('      setvar "qemu_args" "-cpu qemu64,+vmx,+ssse3,+sse4_1,+sse4_2,+aes,+avx,+pat,+pclmulqdq,+rdtscp,+syscall,+tsc-deadline,+x2apic,+xsave";')
	retval.append("         install \"" + config_dir + i + ".conf\" \"/root/junos.base.conf\";")
	retval.append('      interface "vio0" { bridge "' + mgmt_bridge + '"; };')
	for j in d1['vm'][i]['interfaces'].keys():
		if j != "fxp0":
			intf_list.append(j)	
	intf_list.sort()
	for j in intf_list:
		intf_name = "vio" + str(int(j.split("/")[2]) + 1)
		retval.append('      interface "' +  intf_name + '" { bridge "' + d1['vm'][i]['interfaces'][j]['bridge'] + '";};')
	retval.append('};')
	return retval
