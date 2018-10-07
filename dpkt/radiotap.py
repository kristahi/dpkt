# -*- coding: utf-8 -*-
"""Radiotap"""
from __future__ import print_function
from __future__ import absolute_import

import socket

from . import dpkt
from . import ieee80211
from .decorators import deprecated

# Ref: http://www.radiotap.org

# Present flags
_TSFT = 0
_FLAGS = 1
_RATE = 2
_CHANNEL = 3
_FHSS = 4
_ANT_SIG = 5
_ANT_NOISE = 6
_LOCK_QUAL = 7
_TX_ATTN = 8
_DB_TX_ATTN = 9
_DBM_TX_POWER = 10
_ANTENNA = 11
_DB_ANT_SIG = 12
_DB_ANT_NOISE = 13
_RX_FLAGS = 14
_CHANNELPLUS = 18 # Not quite standardized
_EXT = 31

""" # FIXME unused?
# Flags elements
_FLAGS_SIZE = 2
_CFP_FLAG = 0
_PREAMBLE = 1
_WEP = 2
_FRAG = 3
_FCS = 4
_DATA_PAD = 5
_BAD_FCS = 6
_SHORT_GI = 7"""

# Channel type
_CHAN_TYPE_SIZE = 4
_CHANNEL_TYPE = 4
_TURBO = 4
_CCK = 5
_OFDM = 6
_TWO_GHZ = 7
_FIVE_GHZ = 8
_PASSIVE = 9
_DYN_CCK_OFDM = 10
""" # FIXME unused
_GFSK = 11
_GSM = 12
_STATIC_TURBO = 13
_HALF_RATE = 14
_QUARTER_RATE = 15
"""

# Flags offsets and masks
_FCS = 4
_FCS_MASK = 0x10


class Radiotap(dpkt.Packet):
    """Radiotap.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of Radiotap.
        TODO.
    """

    __hdr__ = (
        ('version', 'B', 0),
        ('pad', 'B', 0),
        ('length', 'H', 0),
        ('present_flags', 'I', 0)
    )

    __byte_order__ = '<'

    def _pf_getter(self, flag):
        return (self.present_flags & (2**flag)) >> flag

    def _pf_setter(self, val, flag):
        if val:
            self.present_flags |= 2**flag
        else:
            self.present_flags &= ~(2**flag)

    @property
    def tsft_present(self):
        return self. _pf_getter(_TSFT)

    @tsft_present.setter
    def tsft_present(self, val):
        self._pf_setter(val, _TSFT)

    @property
    def flags_present(self):
        return self._pf_getter(_FLAGS)

    @flags_present.setter
    def flags_present(self, val):
        self._pf_setter(val, _FLAGS)

    @property
    def rate_present(self):
        return self._pf_getter(_RATE)

    @rate_present.setter
    def rate_present(self, val):
        self._pf_setter(val, _RATE)

    @property
    def channel_present(self):
        return self._pf_getter(_CHANNEL)

    @channel_present.setter
    def channel_present(self, val):
        self._pf_setter(val, _CHANNEL)

    @property
    def fhss_present(self):
        return self._pf_getter(_FHSS)

    @fhss_present.setter
    def fhss_present(self, val):
        self._pf_setter(val, _FHSS)

    @property
    def ant_sig_present(self):
        return self._pf_getter(_ANT_SIG)

    @ant_sig_present.setter
    def ant_sig_present(self, val):
        self._pf_setter(val, _ANT_SIG)

    @property
    def ant_noise_present(self):
        return self._pf_getter(_ANT_NOISE)

    @ant_noise_present.setter
    def ant_noise_present(self, val):
        self._pf_setter(val, _ANT_NOISE)

    @property
    def lock_qual_present(self):
        return self._pf_getter(_LOCK_QUAL)

    @lock_qual_present.setter
    def lock_qual_present(self, val):
        self._pf_setter(val, _LOCK_QUAL)

    @property
    def tx_attn_present(self):
        return self._pf_getter(_TX_ATTN)

    @tx_attn_present.setter
    def tx_attn_present(self, val):
        self._pf_setter(val, _TX_ATTN)

    @property
    def db_tx_attn_present(self):
        return self._pf_getter(_DB_TX_ATTN)

    @db_tx_attn_present.setter
    def db_tx_attn_present(self, val):
        self._pf_setter(val, _DB_TX_ATTN)

    @property
    def dbm_tx_power_present(self):
        return self._pf_getter(_DBM_TX_POWER)

    @dbm_tx_power_present.setter
    def dbm_tx_power_present(self, val):
        self._pf_setter(val, _DBM_TX_POWER)

    @property
    def ant_present(self):
        return self._pf_getter(_ANTENNA)

    @ant_present.setter
    def ant_present(self, val):
        self._pf_setter(val, _ANTENNA)

    @property
    def db_ant_sig_present(self):
        return self._pf_getter(_DB_ANT_SIG)

    @db_ant_sig_present.setter
    def db_ant_sig_present(self, val):
        self._pf_setter(val, _DB_ANT_SIG)

    @property
    def db_ant_noise_present(self):
        return self._pf_getter(_DB_ANT_NOISE)

    @db_ant_noise_present.setter
    def db_ant_noise_present(self, val):
        self._pf_setter(val, _DB_ANT_NOISE)

    @property
    def rx_flags_present(self):
        return self._pf_getter(_RX_FLAGS)

    @rx_flags_present.setter
    def rx_flags_present(self, val):
        self._pf_setter(val, _RX_FLAGS)

    @property
    def chanplus_present(self):
        return self._pf_getter(_CHANNELPLUS)

    @chanplus_present.setter
    def chanplus_present(self, val):
        self._pf_setter(val, _CHANNELPLUS)

    @property
    def ext_present(self):
        return self._pf_getter(_EXT)

    @ext_present.setter
    def ext_present(self, val):
        self._pf_setter(val, _EXT)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        #self.data = buf[socket.ntohs(self.length):]
        self.data = buf[self.length:]

        self.fields = []
        self.raw_radiotap = buf[:self.length]
        buf = buf[self.__hdr_len__:]

        # decode each field into self.<name> (eg. self.tsft) as well as append it self.fields list
        field_decoder = [
            ('tsft', self.tsft_present, self.TSFT),
            ('flags', self.flags_present, self.Flags),
            ('rate', self.rate_present, self.Rate),
            ('channel', self.channel_present, self.Channel),
            ('fhss', self.fhss_present, self.FHSS),
            ('ant_sig', self.ant_sig_present, self.AntennaSignal),
            ('ant_noise', self.ant_noise_present, self.AntennaNoise),
            ('lock_qual', self.lock_qual_present, self.LockQuality),
            ('tx_attn', self.tx_attn_present, self.TxAttenuation),
            ('db_tx_attn', self.db_tx_attn_present, self.DbTxAttenuation),
            ('dbm_tx_power', self.dbm_tx_power_present, self.DbmTxPower),
            ('ant', self.ant_present, self.Antenna),
            ('db_ant_sig', self.db_ant_sig_present, self.DbAntennaSignal),
            ('db_ant_noise', self.db_ant_noise_present, self.DbAntennaNoise),
            ('rx_flags', self.rx_flags_present, self.RxFlags)
        ]
        for name, present_bit, parser in field_decoder:
            if present_bit:
                field = parser(buf)
                field.data = b''
                setattr(self, name, field)
                self.fields.append(field)
                buf = buf[len(field):]

        if len(self.data) > 0:
            if self.flags_present and self.flags.fcs:
                self.data = ieee80211.IEEE80211(self.data, fcs=self.flags.fcs)
            else:
                self.data = ieee80211.IEEE80211(self.data)

    class Antenna(dpkt.Packet):
        __hdr__ = (
            ('index', 'B', 0),
        )

    class AntennaNoise(dpkt.Packet):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class AntennaSignal(dpkt.Packet):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class Channel(dpkt.Packet):
        __hdr__ = (
            ('freq', 'H', 0),
            ('flags', 'H', 0),
        )

        __byte_order__ = '<'

        @property
        def turbo(self): return (self.flags & (2**_TURBO)) >> _TURBO

        @turbo.setter
        def turbo(self):
            self.flags |= val << _TURBO

        @property
        def cck(self): return (self.flags & (2**_CCK)) >> _CCK

        @cck.setter
        def cck(self):
            self.flags |= val << _CCK

        @property
        def ofdm(self): return (self.flags & (2**_OFDM)) >> _OFDM

        @ofdm.setter
        def ofdm(self):
            self.flags |= val << _OFDM

        @property
        def two_ghz(self): return (self.flags & (2**_TWO_GHZ)) >> _TWO_GHZ

        @two_ghz.setter
        def two_ghz(self):
            self.flags |= val << _TWO_GHZ

        @property
        def five_ghz(self): return (self.flags & (2**_FIVE_GHZ)) >> _FIVE_GHZ

        @five_ghz.setter
        def five_ghz(self):
            self.flags |= val << _FIVE_GHZ

        @property
        def passive(self): return (self.flags & (2**_PASSIVE)) >> _PASSIVE

        @passive.setter
        def passive(self):
            self.flags |= val << _PASSIVE

        @property
        def dyn_cck_ofdm(self): return (self.flags & (2**_DYN_CCK_OFDM)) >> _DYN_CCK_OFDM

        @dyn_cck_ofdm.setter
        def dyn_cck_ofdm(self):
            self.flags |= val << _DYN_CCK_OFDM

        @property
        def gfsk(self): return (self.flags & (2**_GFSK)) >> _GFSK

        @gfsk.setter
        def gfsk(self):
            self.flags |= val << _GFSK

        # Wireshark also supports several other flags defined in the non-standard
        # Channel+/ChannelX field type, not including them for now.

    class FHSS(dpkt.Packet):
        __hdr__ = (
            ('set', 'B', 0),
            ('pattern', 'B', 0),
        )

    class Flags(dpkt.Packet):
        __hdr__ = (
            ('val', 'B', 0),
        )

        @property
        def fcs(self): return (self.val & _FCS_MASK) >> _FCS

        @fcs.setter
        def fcs(self, v):
            if v:
                self.val |= _FCS_MASK
            else:
                self.val &= ~_FCS_MASK


    class LockQuality(dpkt.Packet):
        __hdr__ = (
            ('val', 'H', 0),
        )

    class RxFlags(dpkt.Packet):
        __hdr__ = (
            ('val', 'H', 0),
        )

        __byte_order__ = '<'

    class Rate(dpkt.Packet):
        __hdr__ = (
            ('val', 'B', 0),
        )

    class TSFT(dpkt.Packet):
        __hdr__ = (
            ('usecs', 'Q', 0),
        )

        __byte_order__ = '<'

    class TxAttenuation(dpkt.Packet):
        __hdr__ = (
            ('val', 'H', 0),
        )

        __byte_order__ = '<'

    class DbTxAttenuation(dpkt.Packet):
        __hdr__ = (
            ('db', 'H', 0),
        )

        __byte_order__ = '<'

    class DbAntennaNoise(dpkt.Packet):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class DbAntennaSignal(dpkt.Packet):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class DbmTxPower(dpkt.Packet):
        __hdr__ = (
            ('dbm', 'B', 0),
        )


def test_Radiotap():
    s = b'\x00\x00\x18\x00\x6e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xa8\x81\x02\x00\x00\x00\x00\x00\x00\x00'
    rad = Radiotap(s)
    assert(rad.version == 0)
    assert(rad.present_flags == 0x6e480000)
    assert(rad.tsft_present == 0)
    assert(rad.flags_present == 1)
    assert(rad.rate_present == 1)
    assert(rad.channel_present == 1)
    assert(rad.fhss_present == 0)
    assert(rad.ant_sig_present == 1)
    assert(rad.ant_noise_present == 1)
    assert(rad.lock_qual_present == 0)
    assert(rad.db_tx_attn_present == 0)
    assert(rad.dbm_tx_power_present == 0)
    assert(rad.ant_present == 1)
    assert(rad.db_ant_sig_present == 0)
    assert(rad.db_ant_noise_present == 0)
    assert(rad.rx_flags_present == 1)
    assert(rad.channel.freq == 0x6c09)
    assert(rad.channel.flags == 0xa000)
    assert(len(rad.fields) == 7)


def test_fcs():
    s = b'\x00\x00\x1a\x00\x2f\x48\x00\x00\x34\x8f\x71\x09\x00\x00\x00\x00\x10\x0c\x85\x09\xc0\x00\xcc\x01\x00\x00'
    rt = Radiotap(s)
    assert(rt.flags_present == 1)
    assert(rt.flags.fcs == 1)


if __name__ == '__main__':
    test_Radiotap()
    test_fcs()
    print('Tests Successful...')
