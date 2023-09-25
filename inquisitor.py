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

from scapy.all import ARP, Ether
import argparse
import sys, os

ARP_TYPE = 0x0806

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

def create_arppkt(IP_src: str, MAC_src: str, IP_target: str, MAC_target: str):
	trame = Ether()
	trame.type = ARP_TYPE

	packet = ARP()
	packet.hwlen = 6
	packet.plen = 4
	try:
		packet.hwsrc = MAC_src
		packet.psrc = IP_src
		packet.hwdst = MAC_target
		packet.pdst = IP_target
	except OSError as error:
		print(f"inquisitor.py: error: {error}")
		exit(1)
	arppckt = trame / packet
	return arppckt

def inquisitor(IP_src: str, MAC_src: str, IP_target: str, MAC_target: str):
	arppkt = create_arppkt(IP_src, MAC_src, IP_target, MAC_target)
	arppkt.show()

if __name__ == "__main__":
	args = parse_arguments()
	if len(sys.argv) != 5:
		exit(1)
	inquisitor(args.IP_src, args.MAC_src, args.IP_target, args.MAC_target)