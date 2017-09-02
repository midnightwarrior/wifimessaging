import coloredlogs
import logging
import os
from scapy.all import *
from reedsolo import *

def send_packet(recipient='', sender='', rssi=0, txpower=0, seqnum=0, rs=None, 
                iface=None):
  
    response = bytearray()
    response.extend(recipient)
    response.extend(sender)
    response.extend(bytearray.fromhex('{:02x}'.format(txpower)))
    response.extend(bytearray.fromhex('{:02x}'.format(-1*rssi)))
    response.extend(bytearray.fromhex('{:04x}'.format(seqnum)))
       
    # Apply Reed-Solomon to the data
    rs_data = rs.encode(response)
    dot11 = Dot11(type=2, subtype=0, addr1="FF:FF:FF:FF:FF:FF", 
                  addr2="FF:FF:FF:FF:FF:FF")
    frame = RadioTap()/dot11/LLC()/SNAP()/Raw(load=rs_data)
    
    sendp(frame, iface=iface)

def decode_packet(data=None):
    # Data packet is never longer than 16 bytes
    data = data[0x00:0x10]
    recipient = str(data[0x00:0x06])
    sender = str(data[0x06:0x0C])
    txpower = int(str(data[0x0C:0x0D]).encode('hex'), 16)
    rssi = -1*int(str(data[0x0D:0x0E]).encode('hex'), 16)
    seqnum = int(str(data[0x0E:0x10]).encode('hex'), 16)
    
    return recipient, sender, txpower, rssi, seqnum

def setupLogging(LOG_LEVEL="DEBUG"):
    coloredlogs.install(level=LOG_LEVEL)
    logger = logging.getLogger(__name__)

    if not os.path.exists("logs"):
        os.mkdir("logs")
    hdlr = logging.FileHandler(os.path.join("logs", 
                               time.strftime("%c").replace(' ', '_')))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)

    return logger
