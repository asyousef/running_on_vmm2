#!/bin/bash
for i in {1..9}
do
echo "server q-pod0${i}"
ssh  q-pod0${i}-vmm.englab.juniper.net "vmm capacity -g vmm-default"
done
for i in {10..26}
do
echo "server q-pod${i}"
ssh q-pod${i}-vmm.englab.juniper.net "vmm capacity -g vmm-default"
done
for i in {1..4}
do
echo "server sv8-pod${i}"
ssh sv8-pod${i}-vmm.englab.juniper.net "vmm capacity -g vmm-default"
done
echo "server wf-pod01"
ssh  wf-pod01-vmm.englab.juniper.net "vmm capacity -g vmm-default"
