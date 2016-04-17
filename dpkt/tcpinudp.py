"""TCP-in-UDP"""

import dpkt
import struct
import socket

fid_portmap = {}

TIU_CHKSUMURP = '\x00\x00\x00\x00'
TIU_SETUPOPT = '\xfd\x05\x52\x4a'

class TiU(dpkt.Packet):
    __hdr__ = (
        ('_off', 'B', ((5 << 4) | 0)),
        ('flags', 'B', 0)
    )
    srcport = 0
    dstport = 0
    fid = -1
    off = 0
    tcpbuf = ''

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        off = self._off >> 4
        if off > 4:
            fid = ((self._off & 0x0f) << 1) + ((self.flags & 0x20) >> 5)
        else:
            fidpos = buf.find(TIU_SETUPOPT)
            if fidpos < 0:
                self.tcpbuf = None
                return
            fid = struct.unpack_from('B', buf, fidpos + 4)[0]

        #Rearrange stuff
        if off == 4:
            hdrlen = len(buf)
            if hdrlen > 60:
                self.tcpbuf = None
                return

            noff = str(struct.pack('B', hdrlen / 4 << 4))
            #Swap the fields
            self.tcpbuf = buf[12:16] + buf[4:12] + noff + buf[1:4] + buf[16:]

            srcport, dstport = [socket.ntohs(p) for p in struct.unpack_from('HH', buf, 12)]
            fid_portmap[fid] = (srcport, dstport)
        else:
            #Inflate header
            srcport, dstport = fid_portmap[fid]
            self.tcpbuf = str(struct.pack('HH', socket.htons(srcport),
                                          socket.htons(dstport))) \
                   + buf[4:12] \
                   + buf[0:4] + TIU_CHKSUMURP + buf[12:]

