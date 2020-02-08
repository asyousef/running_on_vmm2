#!/usr/bin/env python3
import sys
import os
import yaml
import lib1
f=open("lab.yaml")
d1=yaml.load(f)
for i in d1['vm'].keys():
	print("VM ",i)
	for j in d1['vm'][i]['interfaces'].keys():
		print("interfaces %s -> bridge %s " %(j,d1['vm'][i]['interfaces'][j]['bridge']))
print("list of bridges")
print(lib1.list_bridge(d1))
