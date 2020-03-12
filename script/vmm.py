#!/usr/bin/env python3
import sys
import os
import yaml
import lib1
# yaml.warnings({'YAMLLoadWarning': False})
config1=lib1.check_argv(sys.argv)
if config1:
	print("configuration ",config1)
	try:
		# load yaml file
		f1=open(config1['config_file'])
		d1=yaml.load(f1,Loader=yaml.FullLoader)
#		print(d1)
		f1.close()
		if config1['cmd'] == 'upload':
			print('Upload configuration to vmm')
			lib1.upload(d1)
		elif config1['cmd'] == 'start':
			print('starting topology on vmm')
			lib1.start(d1)
		elif config1['cmd'] == 'stop':
			print('stop topology on vmm')
			lib1.stop(d1)
		elif config1['cmd'] == 'list':
			print('list of running VM')
			lib1.list_vm(d1)
		elif config1['cmd'] == 'get_serial':
			print('getting serial information for vm')
			lib1.get_serial(d1)
		elif config1['cmd'] == 'get_vga':
			print('getting VGA port information for vm (for VNC)')
			lib1.get_vga(d1)
		elif config1['cmd'] == 'get_ip':
			print('getting IP for vm')
			lib1.get_ip(d1,config1['vm'])
		elif config1['cmd'] == 'config':
			print('config VM ubuntu 1804')
			lib1.config_ubuntu1804(d1)
		else:
			print("wrong argument")
	except FileNotFoundError:
		print("where is the file")
	except PermissionError:
		print("Permission error")
else:
	print("")
