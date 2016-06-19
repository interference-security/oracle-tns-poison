"""
Inguma Penetration Testing Toolkit
Copyright (c) 2006, 2008 Joxean Koret, joxeankoret [at] yahoo.es

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; version 2
of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""
import sys
import struct
import socket

from libtnserrors import TNS_ERROR_CODES, getTnsErrorMessage

versionPacket  = "\x00\x5a\x00\x00\x01\x00\x00\x00"
versionPacket += "\x01\x36\x01\x2c\x00\x00\x08\x00"
versionPacket += "\x7f\xff\x7f\x08\x00\x00\x00\x01"
versionPacket += "\x00\x20\x00\x3a\x00\x00\x00\x00"
versionPacket += "\x00\x00\x00\x00\x00\x00\x00\x00"
versionPacket += "\x00\x00\x00\x00\x34\xe6\x00\x00"
versionPacket += "\x00\x01\x00\x00\x00\x00\x00\x00"
versionPacket += "\x00\x00"
versionPacket += "(CONNECT_DATA=(COMMAND=version))"

TNS_TYPE_CONNECT = 1
TNS_TYPE_ACCEPT = 2
TNS_TYPE_ACK = 3
TNS_TYPE_REFUSE = 4
TNS_TYPE_REDIRECT = 5
TNS_TYPE_DATA = 6
TNS_TYPE_NULL = 7
TNS_TYPE_ABORT = 9
TNS_TYPE_RESEND = 11
TNS_TYPE_MARKER = 12
TNS_TYPE_ATTENTION = 13
TNS_TYPE_CONTROL = 14
TNS_TYPE_MAX = 19

class TNSBasePacket:
    packetLength = "\x08"
    packetChecksum = "\x00\x00"
    packetType = "\x00" #"\x05" # Redirect
    reservedByte = "\x00"
    headerChecksum = "\x00\x00"
    data = ""
    commandData = ""
    dataFlag = "\x00\x00"
    useDataFlag = False

    def getPacket(self):
        data = len(self.data) + 10
        self.packetLength = struct.pack(">h", int(data))
        
        buf = self.packetChecksum
        buf += self.packetType
        buf += self.reservedByte
        buf += self.headerChecksum
        
        if self.dataFlag:
            buf += self.dataFlag

        buf += self.data
        self.packetLength = len(buf)
        buf = struct.pack(">h", self.packetLength) + buf
        
        return buf
    
    def readPacket(self, buf):
        if len(buf) < 8:
            return False
        
        self.packetLength = buf[0:2]
        self.packetChecksum = buf[2:4]
        self.packetType = buf[4:5]
        self.reservedByte = buf[5:6]
        self.headerChecksum = buf[6:8]
        self.data = buf[8:]
        
        return True

    def getPacketType(self):
        return ord(self.packetType)
    
    def getPacketTypeString(self):
        mType = ord(self.packetType)
        
        if mType == TNS_TYPE_CONNECT:
            return "Connect"
        elif mType == TNS_TYPE_ACCEPT:
            return "Accept"
        elif mType == TNS_TYPE_ACK:
            return "Ack"
        elif mType == TNS_TYPE_REFUSE:
            return "Refuse"
        elif mType == TNS_TYPE_REDIRECT:
            return "Redirect"
        elif mType == TNS_TYPE_DATA:
            return "Data"
        elif mType == TNS_TYPE_NULL:
            return "Null"
        elif mType == TNS_TYPE_ABORT:
            return "Abort"
        elif mType == TNS_TYPE_RESEND:
            return "Resend"
        elif mType == TNS_TYPE_MARKER:
            return "Marker"
        elif mType == TNS_TYPE_ATTENTION:
            return "Attention"
        elif mType == TNS_TYPE_CONTROL:
            return "Control"
        elif mType == TNS_TYPE_MAX:
            return "Max"
        else:
            return "Unknown"

class TNSRedirectPacket(TNSBasePacket):

    redirectDataLength = "\x00\x34"
    redirectData = "(DESCRIPTION=(ADDRESS=())"
    
    def getPacket(self):
        data = len(self.redirectData) + 10
        buf = struct.pack(">h", int(data))
        buf += self.packetChecksum
        buf += self.packetType
        buf += self.reservedByte
        buf += self.headerChecksum
        buf += self.redirectDataLength
        buf += self.redirectData
        return buf

class TNSPacket:

    version = 10

    # :1 is the size + 58 of the packet
    basePacket  = "\x00:1\x00\x00\x01\x00\x00\x00"
    basePacket += "\x01\x36\x01\x2c\x00\x00\x08\x00"
    basePacket += "\x7f\xff\x7f\x08\x00\x00\x00\x01"
    # :2 is the real size of the packet
    basePacket += "\x00:2\x00\x3a\x00\x00\x00\x00"
    basePacket += "\x00\x00\x00\x00\x00\x00\x00\x00"
    basePacket += "\x00\x00\x00\x00\x34\xe6\x00\x00"
    basePacket += "\x00\x01\x00\x00\x00\x00\x00\x00"
    basePacket += "\x00\x00"

    # :1 is the size + 58 of the packet
    base10gPacket  = "\x00:1\x00\x00\x01\x00\x00\x00"
    base10gPacket += "\x01\x39\x01\x2c\x00\x81\x08\x00"
    base10gPacket += "\x7f\xff\x7f\x08\x00\x00\x01\x00"
    # :2 is the real size of the packet
    base10gPacket += "\x00:2\x00\x3a\x00\x00\x07\xf8"
    base10gPacket += "\x0c\x0c\x00\x00\x00\x00\x00\x00"
    base10gPacket += "\x00\x00\x00\x00\x00\x00\x00\x00"
    base10gPacket += "\x00\x00\x00\x00\x00\x00\x00\x00"
    base10gPacket += "\x00\x00"

    def getPacket(self, cmd):
        hLen1 = len(cmd) + 58
        hLen2 = len(cmd)

        x1 = str(hex(hLen1)).replace("0x", "")
        x2 = str(hex(hLen2)).replace("0x", "")
        
        if len(x1) == 1:
            x1 = "0" + x1
        
        if len(x2) == 1:
            x2 = "0" + x2

        hLen1 = eval("'\\x" + x1 + "'")
        hLen2 = eval("'\\x" + x2 + "'")

        if self.version >= 10:
            data = self.base10gPacket
        else:
            data = self.basePacket

        data = data.replace(":1", hLen1)
        data = data.replace(":2", hLen2)
        data += cmd

        return data

class TNS:

    TNS_TYPE_ACCEPT = 0
    TNS_TYPE_ERROR  = 1

    TNS_V7  =  7
    TNS_V8  =  8
    TNS_V9  =  9
    TNS_V10 = 10
    TNS_V11 = 11

    tns_data = None
    banner = None

    def sendCommand(self, command):
        pass

    def sendData(self, data):
        pass

    def sendConnectRequest(self, mSocket, mBuf):
        mSocket.send(mBuf)

    def recvTNSPkt(self, mSocket):
        packet = ""
        packet = mSocket.recv(1024)

        self.tns_data = packet

        if packet.find("(ERR=0)") > 0:
            self.packet_type = TNS.TNS_TYPE_ACCEPT
        else:
            self.packet_type = TNS.TNS_TYPE_ERROR

    def recvAcceptData(self, mSocket, mData):
        packet = ""
        packet = mSocket.recv(1024)

        self.banner = packet

        return(self.tns_data + self.banner)

    def assignVersion(self, data):

        if not str(data).isalnum():
            return

        v = hex(int(data))
        v = v[0:3]
        v = eval(v)

        return(v)
    
    def getTnsError(self, code):
        return getTnsErrorMessage(code)
    
    def getPropertyValue(self, data, property):
        pos    = data.find(property + "=")

        if pos == -1:
            return None

        endPos = data.find(")", pos)
        data = data[pos+len(property)+1:endPos]

        return data
    
    def extractErrorcode(self, data):
        errCode = self.getPropertyValue(data, "CODE")

        if errCode:
            if len(errCode) < 5:
                errCode = "0"*(5-len(errCode)) + errCode

            return errCode

    def getVSNNUM(self, verInfo):
        return self.getPropertyValue(verInfo, "VSNNUM")

class TNSCONNECT:

    def getVersionCommand(self):
        global versionPacket

        return versionPacket

class TNSParser:

    data = ""

    def __init__(self, data):
        if data:
            self.data = data
    
    def getValueFor(self, thekey, single = False):
        buf = []
        level = 0
        value = False
        flag = False
        word = ""

        for char in self.data:
            if char == "(":
                level += 1
                key = ""
                if value:
                    flag = True

                word = ""
            elif char == ")":
            
                if key.lower() == thekey.lower():
                    if not single:
                        buf.append(word)
                    else:
                        single = word
                        break

                level -= 1
                value = False
                word = ""
            elif char == "=":
                value = True
                key = word
                word = ""
            else:
                word += char

        return buf

class TNSDataFormatter:

    data = ""

    def __init__(self, data):
        if data:
            self.data = data
    
    def format(self):
        buf = "\r\n"
        level = 0
        value = False
        flag = False
        word = ""

        for char in self.data:
            if char == "(":
                level += 1
                if value:
                    flag = True
                    buf += "\r\n"

                buf += "  " + "  "*level
                word = ""
            elif char == ")":
                level -= 1
                value = False
                buf += "\r\n"
                word = ""
            elif char == "=":
                value = True
                buf += ": "
                word = ""
            else:
                buf += char
                word += char

        return buf
