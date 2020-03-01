#!/usr/bin/env python3
home_dir='/vmm/data/user_disks/'
pc_type=['pcsmall','pcmedium','pcbig','pcxbig']
vm_type={
   'gw': {'ncpus' : 1,'memory':2048},
   'pcsmall': {'ncpus' : 1,'memory':4096},
   'pcmedium': {'ncpus' : 2,'memory':16384},
   'pcbig': {'ncpus' : 4,'memory':32768},
   'pcxbig': {'ncpus' : 8,'memory':65536},
   'junos': '',
   'wrt': {'ncpus' : 1,'memory':1024},
}
# vm_os=['centos','ubuntu','vmx','vqfx','vsrx','evo','mx960','mx480','mx240','wrt']
vm_os=['centos','centosx','ubuntu','ubuntu1804','vmx','vqfx','vsrx','evo','mx960','mx480','mx240']
tmp_dir="./tmp/"
vmm_group="-g vmm-default"

