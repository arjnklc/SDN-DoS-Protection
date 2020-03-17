# SDN-DoS-Protection

A simple Denial-of-Service (DoS) protection program for Software Defined Networks (SDN). It is implemented on top of ONOS controller. It captures incoming network packets and decides if packets are flood or not with frequency analysis.


# Usage

ONOS 2.0.0 or higher version must be installed.

You can simulate a flood attack with arj_topo.py and dos.py file after installing Mininet http://mininet.org/


arj_topo.py creates a simple topology for virtual network with two hosts and one switch. 

$ sudo mn --custom arj_topo.py --topo arj_topo --controller remote,ip=172.17.0.7 


After topology is created, you can run dos.py to simulate different flood attacks from one host to another host.

