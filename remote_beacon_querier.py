# Demo - continuously send requests to a beacon
# Matthew Bridle, ZL2MNB (Github: @midnightwarrior)

# This work is licensed under a Creative Commons Attribution-NonCommercial 4.0 International License.

from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump,Raw,IP,UDP,sniff,ICMP,LLC,SNAP
from reedsolo import *
import coloredlogs
import logging
import time
import os
import sys
from constants import *
import commonfunctions
    
def main():
    while(1):
        for seqnum in range(0, 65535):
          logging.info("Sending packet to: %s, from: %s, transmit power: %i dBm,"
                       " sequence number: %i" %
                       (recipient_callsign, my_callsign, my_txpower, seqnum))
                       
          commonfunctions.send_packet(recipient=recipient_callsign, sender=my_callsign, 
                                      txpower=my_txpower, seqnum=seqnum, rs=rs,
                                      iface=iface)

          sniff(iface=iface, prn=sniffmgmt, store=0, timeout=1)
       

def sniffmgmt(p):

    # Make sure the packet has the Scapy Dot11 layer present
    # Eventually remove this stuff, since we don't want unnecessary headers
    if not p.haslayer(Dot11):
        return
        
    if not p.type==2:
        return

    # Can we decode the packet?
    try:
        rs_data = (p[Raw].load)#[:-4]
    except Exception as e:
        logger.debug("Raw not found in packet")
        return
        
    try:
        b = bytearray()
        b.extend(rs_data)
    except Exception as e:
        logger.debug("Cannot store data in byte array: %s" % e)
        return

    if len(b) < 10:
        logger.debug("No packet to decode! Length is %i" % len(b))
        return
        
    try:
        data = rs.decode(b)
        recipient, sender, txpower, rssi_from_packet, seqnum = commonfunctions.decode_packet(undecoded=data, rs=rs)
    except Exception as e:
        logger.error("Packet decode error: %s" % e)
        logger.error("Packet length: %i" % len(b))
        return
        
    if len(p.notdecoded) != 28:
        logger.debug("Not-decoded part of header is not the expected size")
        return
        
    if sender == my_callsign:
        logger.debug("Received my own transmitted frame, ignoring it")
        return
        
    logging.info("Decoded packet from: %s, sent to: %s, transmit power: %i dBm,"
                 " RSSI at sender: %i dBm, sequence number: %i" %
                 (sender, recipient, txpower, rssi_from_packet, seqnum))
        
    try:
        logger.debug(' '.join(hex(ord(x)) for x in p.notdecoded))

        rssi = ord(p.notdecoded[-2:-1])-256
        logger.info("Seqnum %i: RSSI of response according to me is %i dBm" % (seqnum, rssi))
    except Exception as e:
        logger.debug("No RSSI found - error: %s" % e)
        return
        
    pathloss = int(txpower) - rssi
    logger.info("Seqnum %i: Pathloss to %s is %i dB" % (seqnum, sender, 
                                                        pathloss))


logger = commonfunctions.setupLogging(LOG_LEVEL=log_level)
rs = RSCodec(32)
recipient_callsign = sys.argv[1]

main()
