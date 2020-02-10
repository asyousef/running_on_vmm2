# Running VM on VMM
release 0.2 
## Overview
This script is used to create configuration files, which will be used to run VM (Virtual Machines) on Juniper's VMM infastructure.

The supported VMs are :
- VMX
- VQFX
- PC with ubuntu OS (16.04)
- PC with centos OS (7.X)

## Requirement
This script requires the following :
- Python3 (this script requires Python3)
- passlib library (to install use `pip3 install passlib`)
- paramiko library (to install use `pip3 install paramiko`)
- yaml library

## VM images 
Before the script is used, the VM images must be available on the VMM.

Please upload the VM images into directory /vmm/data/user_disks/<your_user_name>

You can copy my images from /vmm/data/user_disks/irzan

### How to create Centos/Ubuntu image.
Please refer to the following URL on how to create [centos](create_centos/README.md)

Please refer to the following URL on how to create [ubuntu](create_ubuntu/README.md)
## Script Files

This tool consist of the following script
- **[vmm.py](script/vmm.py)**
- **[lib1.py](script/lib1.py)**
- **[param1.py](script/param1.py)**
- **[lab.yaml](script/lab.yaml)**

## lib1.py
This script is the library with functions declaration used by the other scripts (`vmm.py`)

## param1.py
This script provide the parameters required by the library

## lab.yaml
This is sample configuration.

please edit this file for the following :
- the VMM pod which will be used
- the username/password to access the VMM pod
- the VM, its type, its OS, management IP address and network interfaces for connection to other devices.

Please refer to the sample configuration 

## vmm.py
This script is the user interface, which will read the configuration `lab.yaml` and call the library from `lib1.py1

There are different arguments required by this script
- argument `upload` : to create VMM configuration files and upload them into VMM pod
- argument `start` : to start the topology inside the VMM
- argument `stop` : to stop the topology inside the VMM
- argument `get_serial` :  to get serial console information of the active VMs in the VMM

## Caution 
- to access the VMM pod, it requires Juniper Unix account and it use passwordless SSH access (it uses ssh key)
- when the script is used to start the topology, any existing running topology will be stopped and unbound. Please backup the existing topology if needed.
- this script will need a GW which will be assigned with IP address from juniper's VMM lab. The rest of the VMs (devices), their interfaces management will be connected to virtual network behind the GW.
- to access the other devices (other than GW), VM GW can be used as jump host, or VM GW can be configured as VPN server using [wireguard](https://www.wireguard.com/install/) or openvpn
 
## How to run the script (Step by step)
- **[Running simple topology](https://github.com/m1r24n/simple_on_vmm)**
- **[openstack + Contrail Lab](https://github.com/m1r24n/openstack_contrail_on_vmm)**
- **[kubernetes + contrail Lab](https://github.com/m1r24n/k8s_contrail_on_vmm)**
- **[Healthbot + NS Lab](https://github.com/m1r24n/HB_NS_on_vmm)**
- **[virtual BNG lab](git remote add origin https://github.com/m1r24n/vbng_on_vmm)**

