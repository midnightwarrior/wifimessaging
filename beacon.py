from scapy.all import *
from reedsolo import *
import time
import os
import commonfunctions
from constants import *

def main():
    sniff(iface=iface, prn=sniffmgmt, store=0)

def sniffmgmt(p):

    # Make sure the packet has the Scapy Dot11 layer present
    if not p.haslayer(Dot11):
        return

    if p.type != 2:
        return

    try:
        logger.debug("Packet rxed")
        # Can we decode the packet?
        rs_data = (p[Raw].load)
        b = bytearray()
        b.extend(rs_data)
        recipient_from_packet, sender_from_packet, txpower_from_packet, rssi_from_packet, seqnum_from_packet = commonfunctions.decode_packet(undecoded=b, rs=rs)

        try:
            measured_rssi = ord(p.notdecoded[-2:-1])-256
        except Exception as e:
            logger.debug("No RSSI found")


                     
        # ALLSTA is the identifier which all beacons will respond to.             
        if recipient_from_packet != my_callsign and recipient_from_packet != "ALLSTA":
            logger.debug("Beacon received but it wasn't for me, not responding")
            return

        if sender_from_packet == my_callsign:
            logger.debug("Received my own transmitted frame, ignoring it")
            return
            
        logging.info("Decoded packet from: %s, sent to: %s, transmit power: %i dBm,"
             " measured RSSI at sender: %i dBm, sequence number: %i" %
             (sender_from_packet, recipient_from_packet, txpower_from_packet, rssi_from_packet, seqnum_from_packet))
    
        # Calculate path loss
        pathloss = int(txpower_from_packet) - measured_rssi
        logger.info("Seqnum %i: RSSI of remote responder according to me is %i dBm" % (seqnum_from_packet, measured_rssi))
        logger.info("Seqnum %i: Pathloss to %s is %i dB" % (seqnum_from_packet, 
                                                            sender_from_packet, pathloss))
        logger.info("Seqnum %i: Sending reply" % seqnum_from_packet)
        
        commonfunctions.send_packet(sender=my_callsign, recipient=sender_from_packet, rssi=int(measured_rssi), 
                                    txpower=my_txpower, seqnum=seqnum_from_packet, rs=rs, iface=iface)

    except Exception as e:
        logger.debug("That did not work! Error: %s" % e)


logger = commonfunctions.setupLogging(LOG_LEVEL=log_level)
rs = RSCodec(32)

main()
