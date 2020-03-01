#!/bin/bash
for i in {1..9}
do
ping -c 1 q-pod0${i}-vmm.englab.juniper.net
done
for i in {10..26}
do
ping -c 1 q-pod${i}-vmm.englab.juniper.net
done
for i in {1..4}
do
ping -c 1 sv8-pod${i}-vmm.englab.juniper.net
done
ping -c 1 wf-pod01-vmm.englab.juniper.net
