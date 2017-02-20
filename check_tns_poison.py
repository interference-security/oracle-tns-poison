#!/usr/bin/python

"""
For checking if Oracle TNS Listener is vulnerable to remote poisoning or not
Note: Modified code from tnspoisonv1.py.

Oracle 9i, 10g and 11g TNS Listener Poison 0day exploit
Copyright (c) Joxean Koret 2008
"""

import sys
import time
import struct
import socket

from libtns import *

def main(targetHost, targetPort):

    print "[*] [Optional] In another terminal execute the following command (replace eth0 with your network interface):"
    #print "\ttshark -i eth0 -f 'host " + targetHost + " and tcp port " + str(targetPort) + "'"
    print "\ttshark -i eth0 -f 'host %s and tcp port %s'" % (targetHost, targetPort)
    raw_input("\nPress [Enter] to continue")

    pkt = TNSPacket()
    mbuf = pkt.getPacket("(CONNECT_DATA=(COMMAND=service_register_NSGR))")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((targetHost, int(targetPort)))
    print "\n[*] Sending initial buffer ...\n"
    print mbuf + "\n"
    s.send(mbuf)
    print "\n[*] Recevied following data:\n"
    res = s.recv(8192)
    print res + "\n"
    hex_res = ':'.join(x.encode('hex') for x in res)
    #print hex_res
    tns_state_res = hex_res.split(":")[4]
    #print tns_state_res
    print "[+] Perform the following checks (for port 1521 only):"
    print "\t[+] Check in tshark/wireshark for TNS packets."
    print "\t\t[-] Target is vulnerable if TNS packet has ACCEPT."
    print "\t\t[-] Target is not vulnerable if TNS packet has REFUSE."
    if tns_state_res == "02":
        print "\n[+] Found 'Accept' in the received response."
        print "\t[-] Target is vulnerable."
    elif tns_state_res == "04":
        print "\n[+] Found 'Refuse' in the received response."
        print "\t[-] Target is not vulnerable."
    else:
        print "\n[!] Unknown TNS packet type."
    s.close()

def showTnsError(res):
    pos = res.find("DESCRIPTION")
    print "TNS Listener returns an error:"
    print
    print "Raw response:"
    print repr(res)
    print
    print "Formated response:"
    formatter = TNSDataFormatter(res[pos-1:])
    print formatter.format()

    tns = TNS()
    errCode = tns.extractErrorcode(res)

    if errCode:
        print "TNS-%s: %s" % (errCode, tns.getTnsError(errCode))

def usage():
    print "Usage:", sys.argv[0], "<target_address> <target_port>"
    print

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        sys.exit(1)
    else:
        main(sys.argv[1], sys.argv[2])

