#!/usr/bin/env python3
# this library is used to create configuration files to run VM (Centos/Ubuntu) and Junos (VMX/VQFX) on VMM (juniper internal cloud)
# created by mochammad irzan irzan@juniper.net
# 20 october 2019

import sys
import os
import param1
import shutil
import paramiko
 
# from jnpr.junos import Device
# from jnpr.junos.utils.config import Config
from passlib.hash import md5_crypt

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
	cmd_list=['upload','start','stop','get_serial','get_vga','get_ip','list']
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
	print("VM ",vm)
	print("not implemented yet")
	

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

def get_serial(d1):
	ssh=paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	# ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'],password=d1['vmm_pod']['password'])
	ssh.connect(hostname=d1['vmm_pod']['server'],username=d1['vmm_pod']['user'])
	print('-----')
	print("serial port of VM")
	cmd1="vmm list"
	s1,s2,s3=ssh.exec_command(cmd1)
	vm_list=[]
	for i in s2.readlines():
		vm_list.append(i.rstrip().split()[0])	
	for i in vm_list:
		cmd1="vmm args " + i + " | grep \"serial \""
		s1,s2,s3=ssh.exec_command(cmd1)
		for j in s2.readlines():
			print("serial of " + i + " : " + j.rstrip().split()[1])

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
		if d1['vm'][i]['os'] not in vm_os_d1:
			vm_os_d1.append(d1['vm'][i]['os'])
	# print("vm_os_d1 ",vm_os_d1)
	for i in vm_os_d1:
		if i=='vmx':
			str1='#define VMX_DISK0  basedisk "' + home_dir + d1['vmm_pod']['image']['vmx_re'] + '";'
			lab_conf.append(str1)
			str1='#define VMX_DISK1  basedisk "' + home_dir + d1['vmm_pod']['image']['vmx_mpc'] + '";'
			lab_conf.append(str1)
		elif i=='vqfx':
			str1='#define VQFX_RE  basedisk "' + home_dir + d1['vmm_pod']['image']['vqfx_re'] + '";'
			lab_conf.append(str1)
			str1='#define VQFX_COSIM  basedisk "' + home_dir + d1['vmm_pod']['image']['vqfx_cosim'] + '";'
			lab_conf.append(str1)
		elif i=='centos':
			str1='#define CENTOSDISK  basedisk "' + home_dir + d1['vmm_pod']['image']['centos'] + '";'
			lab_conf.append(str1)
		elif i=='ubuntu':
			str1='#define UBUNTUDISK basedisk "' + home_dir + d1['vmm_pod']['image']['ubuntu'] + '";'
			lab_conf.append(str1)
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
	write_pc_config_to_file(d1)
	f1=param1.tmp_dir + "resolv.conf"
	write_to_file(f1,["nameserver 10.49.0.4","nameserver 10.49.0.37"])
	f1=param1.tmp_dir + "01-ip_forward.conf"
	line1=["net.ipv4.ip_forward=1"]
	write_to_file(f1,line1)
	f1=param1.tmp_dir + "rc.local.gw"
	line1=["#!/bin/bash","touch /var/lock/subsys/local","systemctl stop firewalld","systemctl disable firewalld","iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE","echo \"#!/bin/bash\" > /tmp/rc.local","echo \"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\" >> /tmp/rc.local","echo \"touch /var/lock/subsys/local\" >> /tmp/rc.local","cat /tmp/rc.local > /etc/rc.d/rc.local","rm -f /tmp/rc.local","chmod +x /etc/rc.d/rc.local"]
	write_to_file(f1,line1)
	f1=param1.tmp_dir + "rc.local"
	line1=["#!/bin/bash","touch /var/lock/subsys/local","systemctl stop firewalld","systemctl disable firewalld","echo \"#!/bin/bash\" > /tmp/rc.local","echo \"touch /var/lock/subsys/local\" >> /tmp/rc.local","cat /tmp/rc.local > /etc/rc.d/rc.local","rm -f /tmp/rc.local","chmod +x /etc/rc.d/rc.local"]
	write_to_file(f1,line1)
	write_junos_config(d1)
	upload_file_to_server(d1)

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
			if d1['vm'][i]['os'] == 'vmx':
				write_vmx_config(d1,i)
			elif d1['vm'][i]['os'] == 'vqfx':
				write_vqfx_config(d1,i)
			elif d1['vm'][i]['os'] == 'vsrx':
				write_vsrx_config(d1,i)
				
def write_vmx_config(d1,i):
	print("creating vmx config ",i)
	line1=[]
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
}""" % (d1['vm'][i]['interfaces']['fxp0'][1]) )
	f1=param1.tmp_dir + i + ".conf"
	write_to_file(f1,line1)

def write_vqfx_config(d1,i):
	print("creating vqfx config ",i)
	line1=[]
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
}""" % (d1['vm'][i]['interfaces']['em0'][1]) )
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
}""")
	f1=param1.tmp_dir + i + ".conf"
	write_to_file(f1,line1)


def write_vsrx_config(d1,i):
	print("creating vsrx config ",i)
	print("not yet implemented")


def write_pc_config_to_file(d1):
	print("writing pc conf")
	hosts_file=['127.0.0.1	localhost.localdomain localhost','::1		localhost6.localdomain6 localhost6']
	for i in d1['vm'].keys():
		if d1['vm'][i]['type'] != 'junos':
			f1=param1.tmp_dir + "hostname." + i
			write_to_file(f1,[i])
	for i in d1['vm'].keys():
		if d1['vm'][i]['type'] != 'junos':
			if d1['vm'][i]['os']=='centos':
				for j in d1['vm'][i]['interfaces']:
					line1=[]
					if isinstance(d1['vm'][i]['interfaces'][j],list):
						intf=j.replace('em','eth')
						line1.append('NAME=' + intf)
						line1.append('DEVICE='+intf)
						if d1['vm'][i]['interfaces'][j][1].split('/')[0] == '0.0.0.0':
							line1.extend(['TYPE=Ethernet','BOOTPROTO=dhcp','ONBOOT=no'])
						else:
							line1.extend(['TYPE=Ethernet','BOOTPROTO=static','ONBOOT=yes'])
							line1.append('IPADDR=' + d1['vm'][i]['interfaces'][j][1].split('/')[0])
							line1.append('NETMASK=' + prefix2netmask(d1['vm'][i]['interfaces'][j][1].split('/')[1]))
							if(len(d1['vm'][i]['interfaces'][j])==3):
								line1.append('GATEWAY=' + d1['vm'][i]['interfaces'][j][2])
								hosts_file.append(d1['vm'][i]['interfaces'][j][1].split('/')[0] + ' ' + i)
						f1=param1.tmp_dir + "ifcfg-" + intf + "." + i
						write_to_file(f1,line1)
			elif d1['vm'][i]['os']=='ubuntu':
				line1=[]
				line1.append("auto lo")
				line1.append("iface lo inet loopback")
				for j in d1['vm'][i]['interfaces']:
					if isinstance(d1['vm'][i]['interfaces'][j],list):
						intf=j.replace('em','eth')
						if d1['vm'][i]['interfaces'][j    ][1].split('/')[0] == '0.0.0.0':
							line1.append("iface " + intf + " inet dhcp")
						else:	
							line1.append("auto " + intf)
							line1.append("iface " + intf + " inet static")
							line1.append("    address " + d1['vm'][i]['interfaces'][j][1].split('/')[0])
							line1.append("    netmask " + prefix2netmask(d1['vm'][i]['interfaces'][j][1].split('/')[1]))
							if(len(d1['vm'][i]['interfaces'][j])==3):
								line1.append('   gateway ' + d1['vm'][i]['interfaces'][j][2])
								line1.append('   dns-nameservers 10.49.0.4 10.49.0.37 ')
								hosts_file.append(d1['vm'][i]['interfaces'][j][1].split('/')[0] + ' ' + i)
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
		for i in d1['vm'][i]['interfaces'].values():
			if isinstance(i,str):
				if i != 'external':
					if i not in bridge1:
						bridge1.append(i)
			elif isinstance(i,list):
				if i[0] not in bridge1:
					bridge1.append(i[0])
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

def make_config_generic_pc(d1,i):
	retval=[]
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	# print("Make config for GW for vm ",i)
	retval.append('vm "'+i+'" {')
	retval.append('   hostname "'+i+'";')
	if d1['vm'][i]['os']=='centos':
		retval.append('   CENTOSDISK')
	elif d1['vm'][i]['os']=='ubuntu':
		retval.append('   UBUNTUDISK')
	# print("PC Name :",i)
	# print("PC type :",d1['vm'][i]['type'])
	retval.append('   setvar "+qemu_args" "-cpu qemu64,+vmx";')
	retval.append('   ncpus ' + str(param1.vm_type[d1['vm'][i]['type']]['ncpus']) + ';')
	retval.append('   memory ' + str(param1.vm_type[d1['vm'][i]['type']]['memory']) + ';')
	for j in d1['vm'][i]['interfaces'].keys():
		retval.append('   interface "' +  j + '" { bridge "' + get_bridge_name(d1['vm'][i]['interfaces'][j]) + '";};')
	retval.append('   install "' + config_dir + "hostname." + i + '" "/etc/hostname";')
	
	if d1['vm'][i]['os'] == 'centos':
		retval.append('   install "' + config_dir + "hosts" + '" "/etc/hosts";')
		for j in d1['vm'][i]['interfaces'].keys():
			if isinstance(d1['vm'][i]['interfaces'][j],list):
				retval.append('   install "' + config_dir + "ifcfg-" + change_intf(j) + '.' + i + '" "/etc/sysconfig/network-scripts/ifcfg-' + change_intf(j) +  '";')
	elif d1['vm'][i]['os'] == 'ubuntu':
		retval.append('   install "' + config_dir + "hosts" + '" "/etc/hosts";')
		retval.append('   install "' + config_dir + "interfaces." + i + '" "/etc/network/interfaces";')

	return retval

def make_gw_config(d1,i):
	retval=[]
	# config_dir=param1.home_dir + d1['name'] + "/"
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	retval.extend(make_config_generic_pc(d1,i))
	retval.append('   install "' + config_dir + '01-ip_forward.conf" "/etc/sysctl.d/01-ip_forward.conf";' )
	retval.append('   install "' + config_dir + 'rc.local.gw" "/etc/rc.d/rc.local";' )
	retval.append('};')
	return retval
def make_pc_config(d1,i):
	retval=[]
	# config_dir=param1.home_dir + d1['name'] + "/"
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	retval.extend(make_config_generic_pc(d1,i))
	retval.append('   install "' + config_dir + 'resolv.conf" "/etc/resolv.conf";' )
	retval.append('};')
	return retval

def make_junos_config(d1,i):
	retval=[]
	# print("Make config for Junos for vm ",i)
	if d1['vm'][i]['os']=='vmx':
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
			retval.append("            VMX_CONNECT(GE("+ j.split('-')[1].replace('/',',') + "), " + d1['vm'][i]['interfaces'][j] + ")")
	return retval

def make_vmx_config(d1,i):
	retval=[]
	config_dir=param1.home_dir + d1['vmm_pod']['user'] + '/' + d1['name'] + "/"
	# print("make config for VMX ",i)
	# getting the management interface bridge
	fxp=d1['vm'][i]['interfaces']['fxp0']
	if not isinstance(fxp,list):
		print("where is the ip address ? ")
		exit
	else:
		# ip_mgmt=d1['vm'][i]['interfaces']['fxp0'][1]
		retval.append("   ")
		retval.append("   #undef EM_IPADDR")
		retval.append("   #define EM_IPADDR interface \"em0\" { bridge \"" + d1['vm'][i]['interfaces']['fxp0'][0] + "\";};")
		retval.append("   #define VMX_CHASSIS_I2CID 21")
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
	mgmt_bridge=get_bridge_name(d1['vm'][i]['interfaces']['em0'])
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
		retval.append('      interface "' +  intf_name + '" { bridge "' + get_bridge_name(d1['vm'][i]['interfaces'][j]) + '";};')
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

def make_srx_config(d1,i):
	retval=[]
	print("make config for srx ",i)
	retval.append('vm "'+i+'" {')
	retval.append('   hostname "'+i+'";')
	retval.append('};')
	return retval
