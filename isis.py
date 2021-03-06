#! /usr/bin/env python2.5

##     PyRT: Python Routeing Toolkit

##     ISIS module: provides ISIS listener and ISIS PDU parsers

##     Copyright (C) 2001 Richard Mortier <mort@sprintlabs.com>, Sprint ATL

##     This program is free software; you can redistribute it and/or
##     modify it under the terms of the GNU General Public License as
##     published by the Free Software Foundation; either version 2 of the
##     License, or (at your option) any later version.

##     This program is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##     General Public License for more details.

##     You should have received a copy of the GNU General Public License
##     along with this program; if not, write to the Free Software
##     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
##     02111-1307 USA

# refs: http://www.rware.demon.co.uk/isis.htm, RFC1195, RFC1142,

# This is a good deal grimmer than the BGP module since ISIS, by default on
# Ethernet/802.3 links, is encapsulated directly within the frame.  As a
# consequence we need PF_PACKET and SOCK_RAW to get it -- THESE ARE ONLY
# SUPPORTED IN PYTHON >= 2.0.  As a result this will not be as portable as I'd
# like.  Stick to Linux 2.2.x and higher kernels with packet sockets
# (CONFIG_PACKET) enabled; I've tested on RH7.1 std. install.  Also, it must
# run as root :-((

# Explanation of which bits we slurp: we are looking for ISIS packets carried
# in IEEE 802.3 frames.  This means that we have the following octet layout:

# MAC header (IEEE 802.3):

#   ss-ss-ss-ss-ss-ss :: <6:src MAC>
#   dd-dd-dd-dd-dd-dd :: <6:dst MAC>
#   ll-ll             :: <2:length> == 0x05dc == 1500 (payload only)

# LLC header (IEEE 802.2):
#   dsap :: <1:DSAP> == 0xfe ...by RFC1340, p53, "IEEE 802 Numbers of interest"
#   ssap :: <1:SSAP> == 0xfe ...("ISO CLNS IS 8473")
#   ctrl :: <1 or 2: control> == 0x03 ("unnumbered information")

# In fact, from (after some moulinexing :-)
# http://cell-relay.indiana.edu/cell-relay/docs/rfc/1483/1483.4.1.html

# In LLC Encapsulation the protocol of the routed PDU is identified by
# prefixing the PDU by an IEEE 802.2 LLC header, which is possibly followed by
# an IEEE 802.1a SubNetwork Attachment Point (SNAP) header. ...  The presence
# of a SNAP header is indicated by the LLC header value 0xAA-AA-03.

# ...

# The LLC header value 0xFE-FE-03 identifies that a routed ISO PDU (see [6]
# and Appendix B) follows. The Control field value 0x03 specifies Unnumbered
# Information Command PDU.  ... The routed ISO protocol is identified by a one
# octet NLPID field that is part of Protocol Data. NLPID values are
# administered by ISO and CCITT. They are defined in ISO/IEC TR 9577 [6] and
# some of the currently defined ones are listed in Appendix C.

# ...

# Appendix C. Partial List of NLPIDs
#  0x00    Null Network Layer or Inactive Set (not used with ATM)
#  0x80    SNAP
#  0x81    ISO CLNP
#  0x82    ISO ESIS
#  0x83    ISO ISIS
#  0xCC    Internet IP

# ie. we have 14 octets MAC header, 3 octets LLC header, and then we are in
# the ISIS packet, starting with the NLPID 0x83.  Phew.

# Note 1: AFI 49 (pfx on area code) is public CLNS space a la 10.x.x.x in IP

# Note 2: Actually, although the intro. above says this is grimmer, it is in
# fact quite a lot nicer once adjacency is established.  ISIS is a much nicer
# protocol than BGP which sucks high vacuum.

import sys, getopt, string, os.path, struct, time, select, math
from mutils import *
from isis_extra import check_cksum, getifaddrs
from socket import AF_INET, AF_INET6, PF_PACKET, SOCK_RAW, socket,\
                   inet_ntop, inet_pton, htons, error as sockError

#-------------------------------------------------------------------------------

VERSION = "3.0"
INDENT  = "    "

RETX_THRESH = 3
RCV_BUF_SZ  = 2048

MAC_PKT_LEN  = 1514
MAC_HDR_LEN  = 17
ISIS_PKT_LEN = 1500
ISIS_PDU_LEN = ISIS_PKT_LEN-3
ISIS_LLC_HDR = (0xfe, 0xfe, 0x03, 0x83)

ISIS_HDR_LEN       =  8
ISIS_HELLO_HDR_LEN = 19
ISIS_PP_HELLO_HDR_LEN = 12
ISIS_LSP_HDR_LEN   = 19
ISIS_CSN_HDR_LEN   = 25
ISIS_PSN_HDR_LEN   =  9

AllL1ISs = struct.pack("6B", 0x01, 0x80, 0xc2, 0x00, 0x00, 0x14)
AllL2ISs = struct.pack("6B", 0x01, 0x80, 0xc2, 0x00, 0x00, 0x15)

################################################################################

DLIST = []

NLPIDS = { 0x00L: "NULL",
           0x80L: "SNAP",
           0x81L: "CLNP",
           0x82L: "ESIS",
           0x83L: "ISIS",
           0x8EL: "IPV6",
           0xCCL: "IP",
           }
DLIST = DLIST + [NLPIDS]

MSG_TYPES = { 0L:  "NULL",
              2L:  "ESH",
              4L:  "ISH",
              6L:  "RD",
              15L: "L1LANHello",
              16L: "L2LANHello",
              17L: "PPHello",
              18L: "L1LSP",
              20L: "L2LSP",
              24L: "L1CSN",
              25L: "L2CSN",
              26L: "L1PSN",
              27L: "L2PSN",
              }
DLIST = DLIST + [MSG_TYPES]

CIRCUIT_TYPES = { 0L: "reserved", # ignore entire PDU
                  1L: "L1Circuit",
                  2L: "L2Circuit",
                  3L: "L1L2Circuit",
                  }
DLIST = DLIST + [CIRCUIT_TYPES]

FLAGS = {1L: "SUPPORT_IP",
         2L: "SUPPORT_CLNP",
         }
DLIST = DLIST + [FLAGS]

VLEN_FIELDS = { 0L:   "Null",                # null
                1L:   "AreaAddress",         # area address
                2L:   "LSPIISNeighbor",      # ISIS (CLNP) neighbour (in LSP)
                3L:   "ESNeighbor",          # end system (CLNP) neighbour
                4L:   "PartDIS",             #
                5L:   "PrefixNeighbor",      #
                6L:   "IIHIISNeighbor",      # ISIS (CLNP) neighbour (in ISH)
                8L:   "Padding",             # zero padding
                9L:   "LSPEntries",          # LSPs ack'd in this CSNP/PSNP
                10L:  "Authentication",      #
                12L:  "OptionalChecksum",    #
                14L:  "LSPBufferSize",       #

                22L:  "TEIISNeighbor",       #

                128L: "IPIntReach",          # 'internal' reachable IP subnets
                129L: "ProtoSupported",      # NLPIDs this IS can relay
                130L: "IPExtReach",          # 'external' reachable IP subnets
                131L: "IPInterDomInfo",      # interdomain routeing info
                132L: "IPIfAddr",            # IP address(es) of the interface
                133L: "IPAuthInfo_ILLEGAL",  # deprecated
                134L: "TERouterID",          # TE router ID
                135L: "TEIPReach",           # 'wide metric TLV'
                137L: "DynamicHostname",     # dynamic hostname support

                180L: "LeafNode",            #

                211L: "Restart",             # draft-shand-isis-restart-01.txt

                222L: "MultipleTopologyISN", #
                229L: "MultipleTopologies",  #
                232L: "IPv6IfAddr",          #
                235L: "MTIPReach",           #
                236L: "IPv6IPReach",         #
                237L: "MTIPv6IPReach",       #
                240L: "ThreeWayHello",       #

                254L: "IPSumReach",          #
                }
DLIST = DLIST + [VLEN_FIELDS]

STATES = { 0L: "UP",
           1L: "INITIALIZING",
           2L: "DOWN",
           }
DLIST = DLIST + [STATES]

MTID = { 0L: "IPv4 routing topology",
         1L: "IPv4 in-band management",
         2L: "IPv6 routing topology",
         3L: "IPv4 multicast topology",
         4L: "IPv6 multicast topology",
         5L: "IPv6 in-band management"
         }
DLIST = DLIST + [MTID]

SUBTLV_FIELDS = { 3L: "AdminGroup",
                  6L: "IPv4IntAddr",
                  8L: "IPv4NbrAddr",
                  9L: "MaxLinkBwidth",
                  10L: "MaxResLinkBwidth",
                  11L: "UnresBwidth",
                  18L: "TEDefaultMetric"
                  }
DLIST = DLIST + [SUBTLV_FIELDS]

for d in DLIST:
    for k in d.keys():
        d[ d[k] ] = k

################################################################################

def padPkt(tgt_len, pkt):

    pad_len = tgt_len - len(pkt)
    if pad_len > 0:
        full, part = divmod(pad_len, 257)

        pkt = pkt + (full*struct.pack("BB 255s",
                                 VLEN_FIELDS["Padding"], 255, 255*'\000'))
        pkt = pkt + struct.pack("BB %ds" % (part-2, ),
                           VLEN_FIELDS["Padding"], part-2, (part-2)*'\000')
    return pkt

#-------------------------------------------------------------------------------

def parseMacHdr(pkt):

    (dst_mac, src_mac, length, dsap, ssap, ctrl, nlpid) =\
              struct.unpack(">6s 6s H B B B B", pkt[0:MAC_HDR_LEN+1])

    if (dsap, ssap, ctrl, nlpid) != ISIS_LLC_HDR:
        raise LLCExc

    return (src_mac, dst_mac, length, dsap, ssap, ctrl)

#-------------------------------------------------------------------------------

def parseIsisHdr(pkt):

    (nlpid, hdr_len, ver_proto_id, resvd, msg_type, ver, eco, user_eco) =\
            struct.unpack(">8B", pkt[0:ISIS_HDR_LEN])

    return (nlpid, hdr_len, ver_proto_id, resvd,
            msg_type, ver, eco, user_eco)

#-------------------------------------------------------------------------------

def parsePsnHdr(pkt):

    (pdu_len, src_id) = struct.unpack("> H 7s", pkt[:ISIS_PSN_HDR_LEN])

    return (pdu_len, src_id)

#-------------------------------------------------------------------------------

def parseCsnHdr(pkt):

    (pdu_len, src_id, start_lsp_id, end_lsp_id) =\
              struct.unpack("> H 7s 8s 8s", pkt[:ISIS_CSN_HDR_LEN])

    return (pdu_len, src_id, start_lsp_id, end_lsp_id)

#-------------------------------------------------------------------------------

def parseLspHdr(pkt):

    (pdu_len, lifetime, lsp_id, seq_no, cksm, bits) =\
              struct.unpack("> HH 8s LHB", pkt[:ISIS_LSP_HDR_LEN])
    lsp_id = struct.unpack("> 6sBB", lsp_id)

    return (pdu_len, lifetime, lsp_id, seq_no, cksm, bits)

################################################################################

def parseIsisMsg(msg_len, msg, verbose=1, level=0):

    (src_mac, dst_mac, length, dsap, ssap, ctrl) = parseMacHdr(msg)
    (nlpid, hdr_len, ver_proto_id, resvd, msg_type, ver, eco, user_eco) =\
            parseIsisHdr(msg[MAC_HDR_LEN:MAC_HDR_LEN+ISIS_HDR_LEN])

    if verbose > 1:
        print prtbin(level*INDENT, msg[:MAC_HDR_LEN])

    if verbose > 0:
        print level*INDENT +\
              "%s (len=%d):" % (MSG_TYPES[msg_type], length)
        print (level+1)*INDENT +\
              "src mac: %s, dst mac: %s" %\
              (str2hex(src_mac), str2hex(dst_mac))
        print (level+1)*INDENT +\
              "len: %d, LLC: 0x%0.2x.%0.2x.%0.2x" %\
              (length, dsap, ssap, ctrl)

    if verbose > 1:
        print prtbin((level+1)*INDENT,
                     msg[MAC_HDR_LEN:MAC_HDR_LEN+ISIS_HDR_LEN])

    if verbose > 0:
        print (level+1)*INDENT +\
              "hdr_len: %d, protocol id: %d, version: %d, " %\
              (hdr_len, ver_proto_id, ver) +\
              "eco: %d, user eco: %d" % (eco, user_eco)

    rv = {"T": msg_type,
          "L": msg_len,
          "H": {},
          "V": {}
          }

    rv["H"]["SRC_MAC"] = src_mac
    rv["H"]["DST_MAC"] = dst_mac
    rv["H"]["LENGTH"]  = length
    rv["H"]["DSAP"]    = dsap
    rv["H"]["SSAP"]    = ssap
    rv["H"]["CTRL"]    = ctrl

    rv["H"]["NLPID"]        = nlpid
    rv["H"]["HDR_LEN"]      = hdr_len
    rv["H"]["VER_PROTO_ID"] = ver_proto_id
    rv["H"]["VER"]          = ver
    rv["H"]["ECO"]          = eco
    rv["H"]["USER_ECO"]     = user_eco

    msg = msg[MAC_HDR_LEN+ISIS_HDR_LEN:]
    if msg_type in MSG_TYPES.keys():
        if   msg_type in (MSG_TYPES["L1LANHello"], MSG_TYPES["L2LANHello"]):
            (rv["V"]["CIRCUIT_TYPE"],
             rv["V"]["SRC_ID"],
             rv["V"]["HOLDTIMER"],
             rv["V"]["PDU_LEN"],
             rv["V"]["PRIO"],
             rv["V"]["LAN_ID"],
             rv["V"]["VFIELDS"]) = parseIsisIsh(msg_len, msg, verbose, level)

        elif msg_type == MSG_TYPES["PPHello"]:
            (rv["V"]["CIRCUIT_TYPE"],
             rv["V"]["SRC_ID"],
             rv["V"]["HOLDTIMER"],
             rv["V"]["PDU_LEN"],
             rv["V"]["LOCAL_CIRCUIT_ID"],
             rv["V"]["VFIELDS"]) = parseIsisPPIsh(msg_len, msg, verbose, level)

        elif msg_type in (MSG_TYPES["L1LSP"], MSG_TYPES["L2LSP"]):
            (rv["V"]["PDU_LEN"],
             rv["V"]["LIFETIME"],
             rv["V"]["LSP_ID"],
             rv["V"]["SEQ_NO"],
             rv["V"]["CKSM"],
             rv["V"]["BITS"],
             rv["V"]["VFIELDS"]) = parseIsisLsp(msg_len, msg, verbose, level)

        elif msg_type in (MSG_TYPES["L1CSN"], MSG_TYPES["L2CSN"]):
            (rv["V"]["PDU_LEN"],
             rv["V"]["SRC_ID"],
             rv["V"]["START_LSP_ID"],
             rv["V"]["END_LSP_ID"],
             rv["V"]["VFIELDS"]) = parseIsisCsn(msg_len, msg, verbose, level)

        elif msg_type in (MSG_TYPES["L1PSN"], MSG_TYPES["L2PSN"]):
            (rv["V"]["PDU_LEN"],
             rv["V"]["SRC_ID"],
             rv["V"]["VFIELDS"]) = parseIsisPsn(msg_len, msg, verbose, level)

        else:
            if verbose > 0:
                print level*INDENT + "[ *** %s *** ]" % MSG_TYPES[msg_type]

    else:
        if verbose > 0:
            print level*INDENT + "[ UNKNOWN ISIS message: ", `msg_type`, " ]"

    return rv

################################################################################

def parseIsisIsh(msg_len, msg, verbose=1, level=0):

    (circuit_type, src_id, holdtimer,
     pdu_len, prio, lan_id) = struct.unpack("> B 6s H H B 7s",
                                            msg[:ISIS_HELLO_HDR_LEN])

    if verbose > 1:
        print prtbin(level*INDENT, msg[:ISIS_HELLO_HDR_LEN])

    if verbose > 0:
        print (level+1)*INDENT +\
              "circuit type: %s, holdtimer: %d, " %\
              (CIRCUIT_TYPES[circuit_type], holdtimer) +\
              "PDU len: %d, priority: %d" % (pdu_len, (prio&0x7f))
        print (level+1)*INDENT + "src id: %s, LAN id: %s" %\
              (str2hex(src_id), str2hex(lan_id))

    vfields = parseVLenFields(msg[ISIS_HELLO_HDR_LEN:], verbose, level)
    return (circuit_type, src_id, holdtimer, pdu_len, prio, lan_id, vfields)

#-------------------------------------------------------------------------------

def parseIsisPPIsh(msg_len, msg, verbose=1, level=0):

    (circuit_type, src_id, holdtimer,
     pdu_len, local_circuit_id) = struct.unpack(">B 6s H H B",
                                  msg[:ISIS_PP_HELLO_HDR_LEN])
    if verbose > 1:
       print prtbin(level*INDENT,msg[:ISIS_PP_HELLO_HDR_LEN])
    if verbose > 0:
        print (level+1)*INDENT +\
              "circuit type: %s, holdtimer: %d, " %\
              (CIRCUIT_TYPES[circuit_type], holdtimer) +\
              "PDU len: %d,"  % (pdu_len)
        print (level+1)*INDENT + "src id: %s,  local circuit id: %s" %\
              (str2hex(src_id), local_circuit_id)

    vfields = parseVLenFields(msg[ISIS_PP_HELLO_HDR_LEN:], verbose, level)
    return (circuit_type, src_id, holdtimer, pdu_len, local_circuit_id, vfields)

#-------------------------------------------------------------------------------

def parseIsisLsp(msg_len, msg, verbose=1, level=0):

    (pdu_len, lifetime, lsp_id, seq_no, cksm, bits) = parseLspHdr(msg)

    cksm_ok, cksm_msg = check_cksum (msg, 4, pdu_len - 12, cksm, 16)

    if verbose > 0:

        if verbose > 1:
            print prtbin(level*INDENT, msg[:ISIS_LSP_HDR_LEN])
        print (level+1)*INDENT +\
              "PDU len: %d, lifetime: %d, seq.no: %d, cksm: %s (%s)" %\
              (pdu_len, lifetime, seq_no, int2hex(cksm), cksm_msg)
        print (level+1)*INDENT +\
              "LSP ID: src: %s, pn: %s, LSP no: %d" %\
              (str2hex(lsp_id[0]), int2hex(lsp_id[1]), lsp_id[2])

        p   = bits & (1<<7)
        att = (bits & (1<<6)) * "error " + (bits & (1<<5)) * "expense " +\
              (bits & (1<<4)) * "delay " + (bits & (1<<3)) * "default"
        hty = (bits & (1<<2)) >> 2
        ist = bits & ((1<<1) | (1<<0))

        print (level+1)*INDENT +\
              "partition repair: %s, hippity: %s, type: %s" %\
              (("no", "yes")[p], ("no", "yes")[hty],
               ("UNUSED", "L1", "UNUSED", "L1+L2")[ist])
        print (level+1)*INDENT + "attached: %s" % att

    vfields = parseVLenFields(msg[ISIS_LSP_HDR_LEN:], verbose, level) if cksm_ok else {}
    return (pdu_len, lifetime, lsp_id, seq_no, cksm, bits, vfields)

#-------------------------------------------------------------------------------

def parseIsisCsn(msg_len, msg, verbose=1, level=0):

    (pdu_len, src_id, start_lsp_id, end_lsp_id) = parseCsnHdr(msg)

    if verbose > 0:

        if verbose > 1:
            print prtbin(level*INDENT, msg[:ISIS_CSN_HDR_LEN])
        print (level+1)*INDENT +\
              "PDU len: %d, src ID: %s" % (pdu_len, str2hex(src_id))
        print (level+1)*INDENT +\
              "start LSP ID: %s" % (str2hex(start_lsp_id),)
        print (level+1)*INDENT +\
              "end LSP ID: %s" % (str2hex(end_lsp_id),)

    vfields = parseVLenFields(msg[ISIS_CSN_HDR_LEN:], verbose, level)
    return (pdu_len, src_id, start_lsp_id, end_lsp_id, vfields)

#-------------------------------------------------------------------------------

def parseIsisPsn(msg_len, msg, verbose=1, level=0):

    (pdu_len, src_id) = parsePsnHdr(msg)

    if verbose > 0:

        if verbose > 1:
            print prtbin(level*INDENT, msg[:ISIS_PSN_HDR_LEN])
        print (level+1)*INDENT +\
              "PDU len: %d, src ID: %s" % (pdu_len, str2hex(src_id))

    vfields = parseVLenFields(msg[ISIS_PSN_HDR_LEN:], verbose, level)
    return (pdu_len, src_id, vfields)

################################################################################

def parseVLenFields(fields, verbose=1, level=0):

    vfields = {}

    while len(fields) > 1:
        # XXX: strange -- have seen single null byte vfields...

        (ftype, flen) = struct.unpack(">BB", fields[0:2])

        if not vfields.has_key(ftype):
            vfields[ftype] = []

        vfields[ftype].append(
            parseVLenField(ftype, flen, fields[2:2+flen], verbose, level+1)
            )

        fields = fields[2+flen:]

    return vfields

#-------------------------------------------------------------------------------

def parseVLenField(ftype, flen, fval, verbose=1, level=0):

    rv = { "L" : flen,
           }

    if verbose > 1 and ftype not in (VLEN_FIELDS["Padding"],
                                     VLEN_FIELDS["Null"]):
        print prtbin(level*INDENT, `ftype`+`flen`+fval)

    if ftype in VLEN_FIELDS.keys():
        if verbose > 0 and ftype not in (VLEN_FIELDS["Padding"],
                                         VLEN_FIELDS["Null"]):
            print level*INDENT +\
                  "field: %s, length: %d" % (VLEN_FIELDS[ftype], flen)

        level = level + 1
        if   ftype == VLEN_FIELDS["Null"]:
            pass

        elif ftype == VLEN_FIELDS["AreaAddress"]:
            ## 1
            rv["V"] = []
            areas = ""
            while len(fval) > 0:

                (l,) = struct.unpack("> B", fval[0])

                rv["V"].append(fval[1:1+l])

                areas = areas + '0x' + str2hex(fval[1:1+l]) + ", "
                fval = fval[1+l:]

            if verbose > 0:
                print level*INDENT + "area addresses: " + areas

        elif ftype == VLEN_FIELDS["LSPIISNeighbor"]:
            ## 2
            rv["V"] = []
            vflag = struct.unpack("> B", fval[0])
            fval  = fval[1:]
            cnt   = 0
            while len(fval) > 0:
                cnt = cnt + 1
                default, delay, expense, error, nid =\
                         struct.unpack("> BBBB 7s", fval[0:11])

                is_neighbour = { 'DEFAULT': default,
                                 'DELAY'  : delay,
                                 'EXPENSE': expense,
                                 'ERROR'  : error,
                                 'NID'    : nid,
                                 }
                rv["V"].append(is_neighbour)

                if verbose > 0:
                    print level*INDENT +\
                          "IS Neighbour %d: id: %s" % (cnt, str2hex(nid))
                    print (level+1)*INDENT +\
                          "default: %d, delay: %d, expense: %d, error: %d" %\
                          (default, delay, expense, error)

                fval = fval[11:]

        elif ftype == VLEN_FIELDS["ESNeighbor"]:
            ## 3
            default, delay, expense, error = struct.unpack("> 4B", fval[0:4])
            rv["V"] = { 'DEFAULT' : default,
                        'DELAY'   : delay,
                        'EXPENSE' : expense,
                        'ERROR'   : error,
                        'NIDS'    : []
                        }

            if verbose > 0:
                print level*INDENT +\
                      "default: %d, delay: %d, expense: %d, error: %d" %\
                      (default, delay, expense, error)

            fval = fval[4:]
            cnt  = 0
            while len(fval) > 0:
                cnt = cnt + 1
                (nid,) = struct.unpack("> 6s", fval[0:6])

                rv["V"]["NIDS"].append(nid)

                if verbose > 0:
                    print level*INDENT +\
                          "ES Neighbour %d: %s" % (cnt, str2hex(nid))

                fval = fval[6:]

        elif ftype == VLEN_FIELDS["IIHIISNeighbor"]:
            ## 6
            rv["V"] = []
            cnt = 0
            while len(fval) > 0:
                cnt = cnt + 1
                (nid,) = struct.unpack("> 6s", fval[0:6])

                rv["V"].append(nid)

                if verbose > 0:
                    print level*INDENT +\
                          "IS Neighbour %d: %s" % (cnt, str2hex(nid))

                fval = fval[6:]

        elif ftype == VLEN_FIELDS["Padding"]:
            ## 8
            rv["V"] = None

        elif ftype == VLEN_FIELDS["LSPEntries"]:
            ## 9
            rv["V"] = []
            cnt = 0
            while len(fval) > 0:
                cnt = cnt + 1
                lifetime, lsp_id, lsp_seq_no, cksm =\
                          struct.unpack("> H 8s L H", fval[:16])
                lsp_id = struct.unpack("> 6sBB", lsp_id)

                lsp_entry = { "ID"       : lsp_id[0],
                              "PN"       : lsp_id[1],
                              "NM"       : lsp_id[2],
                              "LIFETIME" : lifetime,
                              "SEQ_NO"   : lsp_seq_no,
                              "CKSM"     : cksm
                              }

                rv["V"].append(lsp_entry)

                if verbose > 0:
                    print level*INDENT +\
                          "%d: LSP ID: src: %s, pn: %s, LSP no: %d" %\
                          (cnt, str2hex(lsp_id[0]), int2hex(lsp_id[1]), lsp_id[2])
                    print (level+1)*INDENT +\
                          "lifetime: %d, seq.no: %d, cksm: %s" %\
                          (lifetime, lsp_seq_no, int2hex(cksm))

                fval = fval[16:]

        elif ftype == VLEN_FIELDS["Authentication"]:
            ## 10
            AuthType, AuthValue = struct.unpack(">B%ds" % (flen-1), fval)
            rv["V"] = { "TYPE": AuthType, "VALUE": AuthValue }

            if verbose > 0:
                print level*INDENT +\
                            "AuthType %d AuthValue %s" % (AuthType, AuthValue)

        elif ftype == VLEN_FIELDS["TEIISNeighbor"]:
            ## 22 (http://tools.ietf.org/html/rfc5305#page-3)
            rv["V"] = []
            cnt = 0
            while len(fval) > 0:
                cnt += 1
                nid, metric, sublen = struct.unpack("> 7s 3s B", fval[:11])
                fval = fval[11:]

                subfields = fval[:sublen]
                while len(subfields) > 1:
                    stype, slen = struct.unpack(">BB", subfields[:2])
                    subfields = subfields[2:]

                    if verbose > 0:
                        if stype in SUBTLV_FIELDS.keys():
                            print (level+1)*INDENT +\
                                "subfield: %s, length: %d" %\
                                    (SUBTLV_FIELDS[stype], slen)
                        else:
                            print (level+1)*INDENT +\
                                "subfield: UNKNOWN, length: %d" % slen

                    if stype == SUBTLV_FIELDS["IPv4IntAddr"]:
                        (addr,) = struct.unpack(">4s", subfields[:4])
                        if verbose > 0:
                            print (level+2)*INDENT +\
                                "address: " + `inet_ntop(AF_INET, addr)`

                                
                    elif stype == SUBTLV_FIELDS["IPv4NbrAddr"]:
                        (addr,) = struct.unpack(">4s", subfields[:4])
                        if verbose > 0:
                            print (level+2)*INDENT +\
                                "address: " + `inet_ntop(AF_INET, addr)`

                    subfields = subfields[slen:]

                fval = fval[sublen:]

                rv["V"].append({ "NID": nid, "METRIC": metric })

                if verbose > 0:
                    print level*INDENT +\
                            "IS Neighbour %d: id: %s metric: %d" %\
                            (cnt, str2hex(nid), str2int(metric))

        elif ftype == VLEN_FIELDS["IPIntReach"]:
            ## 128
            rv["V"] = []
            cnt = 0
            while len(fval) > 0:
                cnt = cnt + 1
                default, delay, expense, error, addr, mask =\
                         struct.unpack("> 4B LL", fval[0:12])

                ipif = { 'DEFAULT': default,
                         'DELAY'  : delay,
                         'EXPENSE': expense,
                         'ERROR'  : error,
                         'ADDR'   : addr,
                         'MASK'   : mask
                         }
                rv["V"].append(ipif)

                if verbose > 0:
                    print level*INDENT +\
                          "%d: default: %d, delay: %d, expense: %d, error: %d" %\
                          (cnt, default, delay, expense, error)
                    print (level+1)*INDENT +\
                          "addr/mask: %s/%s" % (id2str(addr), id2str(mask))

                fval = fval[12:]

        elif ftype == VLEN_FIELDS["ProtoSupported"]:
            ## 129
            prots = struct.unpack("> %dB" % flen, fval)
            prots_strs = map(lambda x: '%s' % x,
                             map(lambda x: NLPIDS[x], prots))

            rv["V"] = prots_strs

            if verbose > 0:
                print level*INDENT + "protocols supported: " + `prots_strs`

        elif ftype == VLEN_FIELDS["IPExtReach"]:
            ## 130
            rv["V"] = []
            cnt = 0
            while len(fval) > 0:
                cnt = cnt + 1
                default, delay, expense, error, addr, mask =\
                         struct.unpack("> 4B LL", fval[0:12])

                ipif = { 'DEFAULT': default,
                         'DELAY'  : delay,
                         'EXPENSE': expense,
                         'ERROR'  : error,
                         'ADDR'   : addr,
                         'MASK'   : mask
                         }
                rv["V"].append(ipif)

                if verbose > 0:
                    print level*INDENT +\
                          "%d: default: %d, delay: %d, expense: %d, error: %d" %\
                          (cnt, default, delay, expense, error)
                    print (level+1)*INDENT +\
                          "addr/mask: %s/%s" % (id2str(addr), id2str(mask))

                fval = fval[12:]

        elif ftype == VLEN_FIELDS["IPInterDomInfo"]:
            ## 131
            rv["V"] = None

            if verbose > 0:
                print level*INDENT + "[ IPInterDomInfo ]"

        elif ftype == VLEN_FIELDS["IPIfAddr"]:
            ## 132
            rv["V"] = []
            while len(fval) > 0:
                (addr,) = struct.unpack("> 4s", fval[:4])
                rv["V"].append(inet_ntop(AF_INET, addr))
                fval = fval[4:]

            if verbose > 0:
                print level*INDENT + "interface IP addresses: " + `rv["V"]`

        elif ftype == VLEN_FIELDS["TEIPReach"]:
            ## 135 (http://tools.ietf.org/html/rfc5305#page-8)
            rv["V"] = []
            cnt = 0
            while len(fval) > 0:
                cnt = cnt + 1
                metric, control = struct.unpack("> L B", fval[:5])
                fval = fval[5:]

                updown = control & (1 << 7)
                subtlv = control & (1 << 6)
                plen = control & 63

                if plen > 0:
                    nb_bytes = int((plen + 7) / 8)

                    (addr,) = struct.unpack ("> %ds" % nb_bytes, fval[:nb_bytes])
                    addr_str = inet_ntop(AF_INET, addr + "\0"*(4-nb_bytes))
                    fval = fval[nb_bytes:]
                else:
                    addr_str = "0.0.0.0"

                ipif = { 'ADDR'   : addr_str,
                         'PLEN'   : plen,
                         'METRIC' : metric,
                         'UPDOWN' : updown
                         }
                rv["V"].append(ipif)

                if verbose > 0:
                    print level*INDENT +\
                          "prefix %d: %s/%d metric: %d distribution: %s" %\
                          (cnt, addr_str, plen, metric,
                              "down" if updown else "up")

                # Ignore sub-TLVs (if any)
                if subtlv:
                    (subtlv_length,) = struct.unpack ("> B", fval[0])
                    fval = fval[1+subtlv_length:]

        elif ftype == VLEN_FIELDS["DynamicHostname"]:
            ## 137
            (name,) = struct.unpack("> %ds" % flen, fval)
            rv["V"] = name

            if verbose > 0:
                print level*INDENT + "dynamic hostname: '%s'" % name

        elif ftype == VLEN_FIELDS["Restart"]:
            ## 211
            Flags, HoldingTime, RestartingNeighborID =\
                      struct.unpack("> BH%ds" % (flen-3), fval)
            rv["V"] = HoldingTime

            if verbose > 0:
              print level*INDENT +\
                        "Flags: %d HoldingTime: %s RestartingNeighborID: %s" %\
                                  (Flags, HoldingTime, str2hex(RestartingNeighborID))

        elif ftype == VLEN_FIELDS["MultipleTopologyISN"]:
            ## 222
            (mtid,) = struct.unpack("> H", fval[:2])
            mtid &= 4095 # keep only the last 12 bits
            rv["V"] = { 'MTID': mtid, 'NEIGHBORS': [] }

            if verbose > 0:
                if mtid in MTID.keys():
                    mtid_str = MTID[mtid]
                else:
                    mtid_str = "[ UNKNOWN MT ID: %d ]" % mtid
                print level*INDENT + mtid_str

            fval = fval[2:]
            cnt = 0
            while len(fval) > 0:
                cnt += 1
                nid, metric, sublen = struct.unpack("> 7s 3s B", fval[:11])

                rv["V"]["NEIGHBORS"].append({ "NID": nid, "METRIC": metric })

                if verbose > 0:
                    print level*INDENT +\
                            "IS Neighbour %d: id: %s metric: %d" %\
                            (cnt, str2hex(nid), str2int(metric))

                fval = fval[11+sublen:]

        elif ftype == VLEN_FIELDS["MultipleTopologies"]:
            ## 229
            rv["V"] = []
            while len(fval) > 0:
                (row,) = struct.unpack ("> H", fval[:2])

                overload = row & (1 << 7)
                attach = row & (1 << 6)
                mtid = row & 4095
                mt = { 'MTID': mtid,
                       'OVERLOAD': overload,
                       'ATTACH': attach
                       }
                rv["V"].append(mt)

                if verbose > 0:
                    if mtid in MTID.keys():
                        mtid_str = MTID[mtid]
                    else:
                        mtid_str = "[ UNKNOWN MT ID: %d ]" % mtid

                    if overload:
                        mtid_str += ", OVERLOAD bit set"
                    if attach:
                        mtid_str += ", ATTACH bit set"

                    print level*INDENT + mtid_str

                fval = fval[2:]

        elif ftype == VLEN_FIELDS["IPv6IfAddr"]:
            ## 232
            rv["V"] = []
            while len(fval) > 0:
                (addr,) = struct.unpack("> 16s", fval[:16])
                rv["V"].append(inet_ntop(AF_INET6, addr))
                fval = fval[16:]

            if verbose > 0:
                print level*INDENT + "interface IPv6 addresses: " + `rv["V"]`

        elif ftype == VLEN_FIELDS["MTIPReach"]:
            ## 235
            (mtid,) = struct.unpack("> H", fval[:2])
            mtid &= 4095 # keep only the last 12 bits
            rv["V"] = { 'MTID': mtid, 'PREFIXES': [] }

            if verbose > 0:
                if mtid in MTID.keys():
                    mtid_str = MTID[mtid]
                else:
                    mtid_str = "[ UNKNOWN MT ID: %d ]" % mtid
                print level*INDENT + mtid_str

            fval = fval[2:]
            cnt = 0
            while len(fval) > 0:
                cnt += 1
                metric, control = struct.unpack("> L B", fval[:5])
                fval = fval[5:]

                updown = control & (1 << 7)
                subtlv = control & (1 << 6)
                plen = control & 63

                if plen > 0:
                    nb_bytes = int((plen + 7) / 8)

                    (addr,) = struct.unpack ("> %ds" % nb_bytes, fval[:nb_bytes])
                    addr_str = inet_ntop(AF_INET, addr + "\0"*(4-nb_bytes))
                    fval = fval[nb_bytes:]
                else:
                    addr_str = "0.0.0.0"

                ipif = { 'ADDR'   : addr_str,
                         'PLEN'   : plen,
                         'METRIC' : metric,
                         'UPDOWN' : updown
                         }
                rv["V"]["PREFIXES"].append(ipif)

                if verbose > 0:
                    print level*INDENT +\
                          "prefix %d: %s/%d metric: %d distribution: %s" %\
                          (cnt, addr_str, plen, metric,
                              "down" if updown else "up")

                # Ignore sub-TLVs (if any)
                if subtlv:
                    (subtlv_length,) = struct.unpack ("> B", fval[0])
                    fval = fval[1+subtlv_length:]

        elif ftype == VLEN_FIELDS["IPv6IPReach"]:
            ## 236
            metric, control, plen = struct.unpack("> L B B", fval[:6])
            fval = fval[5:]

            updown = control & (1 << 7)
            external = control & (1 << 6)
            subtlv = control & (1 << 5)

            if plen > 0:
                nb_bytes = int((plen + 7) / 8)

                (addr,) = struct.unpack("> %ds" % nb_bytes, fval[:nb_bytes])
                addr_str = inet_ntop(AF_INET6, addr + "\0"*(16-nb_bytes))
                fval = fval[nb_bytes:]
            else:
                addr_str = "::"

            rv["V"] = { 'ADDR'     : addr_str,
                        'PLEN'     : plen,
                        'METRIC'   : metric,
                        'UPDOWN'   : updown,
                        'EXTERNAL' : external
                        }

            if verbose > 0:
                print level*INDENT +\
                      "prefix: %s/%d metric: %d distribution: %s, %s" %\
                      (addr_str, plen, metric,
                          "down" if updown else "up",
                          "external" if external else "internal")

            # Ignore sub-TLVs (if any)
            if subtlv:
                (subtlv_length,) = struct.unpack ("> B", fval[0])
                fval = fval[1+subtlv_length:]

        elif ftype == VLEN_FIELDS["MTIPv6IPReach"]:
            ## 237
            (mtid,) = struct.unpack("> H", fval[:2])
            mtid &= 4095 # keep only the last 12 bits
            rv["V"] = { 'MTID': mtid, 'PREFIXES': [] }

            if verbose > 0:
                if mtid in MTID.keys():
                    mtid_str = MTID[mtid]
                else:
                    mtid_str = "[ UNKNOWN MT ID: %d ]" % mtid
                print level*INDENT + mtid_str

            fval = fval[2:]
            cnt = 0
            while len(fval) > 0:
                cnt += 1
                metric, control, plen = struct.unpack("> L B B", fval[:6])
                fval = fval[6:]

                updown = control & (1 << 7)
                external = control & (1 << 6)
                subtlv = control & (1 << 5)

                if plen > 0:
                    nb_bytes = int((plen + 7) / 8)

                    (addr,) = struct.unpack("> %ds" % nb_bytes, fval[:nb_bytes])
                    addr_str = inet_ntop(AF_INET6, addr + "\0"*(16-nb_bytes))
                    fval = fval[nb_bytes:]
                else:
                    addr_str = "::"

                ifip = { 'ADDR'     : addr_str,
                         'PLEN'     : plen,
                         'METRIC'   : metric,
                         'UPDOWN'   : updown,
                         'EXTERNAL' : external
                         }
                rv["V"]["PREFIXES"].append(ifip)

                if verbose > 0:
                    print level*INDENT +\
                          "prefix %d: %s/%d metric: %d distribution: %s, %s" %\
                          (cnt, addr_str, plen, metric,
                              "down" if updown else "up",
                              "external" if external else "internal")

                # Ignore sub-TLVs (if any)
                if subtlv:
                    (subtlv_length,) = struct.unpack ("> B", fval[0])
                    fval = fval[1+subtlv_length:]

        elif ftype == VLEN_FIELDS["ThreeWayHello"]:
            ## 240
            (state,) = struct.unpack("> B", fval[0])
            rv["V"] = { 'STATE': state }
            twhello_str = STATES[state]

            if flen >= 5:
                (lcid,) = struct.unpack("> L", fval[1:5])
                rv["V"]["LCID"] = lcid
                twhello_str += ", ext. local circuit ID: %d" % lcid

                if flen >= 11:
                    (nbr_sid,) = struct.unpack("> 6s", fval[5:11])
                    rv["V"]["NBR_SID"] = nbr_sid
                    twhello_str += "\n" + level*INDENT + "Neighbor ID: %s" %\
                                      str2hex(nbr_sid)

                    if flen >= 15:
                        (nbr_lcid,) = struct.unpack("> L", fval[11:15])
                        rv["V"]["NBR_LCID"] = nbr_lcid
                        twhello_str += ", neighbor ext. local circuit ID: %d" %\
                                          nbr_lcid

            if verbose >0:
                print level*INDENT + "Adjacency state: " + twhello_str

        else:
            if verbose > 0:
                print level*INDENT + "[ *** %s *** ]" % VLEN_FIELDS[ftype]

    else:
        if verbose > 0:
            print level*INDENT + \
                  "[ UNKNOWN ISIS variable length field: ", `ftype`, " ]"

    return rv

################################################################################

class LLCExc(Exception): pass
class VLenFieldExc(Exception): pass
class InvalidIPAddrExc(Exception): pass
class NoIPAddrExc(Exception): pass

#-------------------------------------------------------------------------------

class Isis:

    _eth_p_802_2 = htons(0x0004)
    _dev_str     = "eth0"

    _version          = 1
    _version_proto_id = 1

    _hold_multiplier  = 3
    _holdtimer        = 10

    #---------------------------------------------------------------------------

    class Adj:

        def __init__(self, atype, ish_rv, tx_ish):

            self._state  = STATES["INITIALIZING"]
            self._type   = atype
            self._tx_ish = tx_ish

            self._rtx_at = 0

            self._nbr_mac_addr = ish_rv["H"]["SRC_MAC"]

            self._holdtimer  = ish_rv["V"]["HOLDTIMER"]
            self._nbr_src_id = ish_rv["V"]["SRC_ID"]

            if ish_rv["T"] == MSG_TYPES["PPHello"]:
                self._nbr_local_circuit_id = ish_rv["V"]["LOCAL_CIRCUIT_ID"]
            else:
                self._nbr_lan_id = ish_rv["V"]["LAN_ID"] 

            self._nbr_areas = []
            if VLEN_FIELDS["AreaAddress"] in ish_rv["V"]["VFIELDS"]:
                for field in ish_rv["V"]["VFIELDS"][VLEN_FIELDS["AreaAddress"]]:
                    for area_addr in field["V"]:
                        self._nbr_areas.append(area_addr)

        def __repr__(self):

            ret = "st: %s, ht: %d, retx: %d, " %\
                    (STATES[self._state], self._holdtimer, self._rtx_at)

            ret += "neighbour areas: %s, nbr src id: %s, " %\
                    (`map(str2hex, self._nbr_areas)`, str2hex(self._nbr_src_id))

            if self._type == 3:
                ret += "local circuit id: %d" % self._nbr_local_circuit_id
            else:
                ret += "lan id: %s" % str2hex(self._nbr_lan_id)

            return ret

    #---------------------------------------------------------------------------

    class LSP:

        def __init__(self, lsp_id, lifetime, seq_no, cksm):

            self._id_src   = lsp_id[0]
            self._id_pn    = lsp_id[1]
            self._id_no    = lsp_id[2]
            self._lifetime = lifetime
            self._seq_no   = seq_no
            self._cksm     = cksm

        def __repr__(self):

            ret = "LSP ID: src: %s, pn: %s, no: %d\n" %\
                  (str2hex(self._id_src), int2hex(self._id_pn), self._id_no)
            ret += "lifetime: %d, seq.no: %d, cksm: %s" %\
                   (self._lifetime, self._seq_no, int2hex(self._cksm))

    #---------------------------------------------------------------------------

    def __init__(self, area_addr, dev=None, src_id=None, lan_id=None, src_ip=None, passwd=None):

        if not dev:
            dev = Isis._dev_str

        self._sock = socket(PF_PACKET, SOCK_RAW, Isis._eth_p_802_2)
        self._sockaddr = (dev, 0x0000)
        self._sock.bind(self._sockaddr)
        self._sockname = self._sock.getsockname()

        if src_ip:
            try:
                self._src_ip = (inet_pton(AF_INET, src_ip),)
                self._src_ip6 = None
                self._proto = [ NLPIDS["IP"] ]

            except sockError:
                try:
                    self._src_ip = None
                    self._src_ip6 = (inet_pton(AF_INET6, src_ip),)
                    self._proto = [ NLPIDS["IPV6"] ]

                except sockError:
                    raise InvalidIPAddrExc

        else:
            iface_addrs = getifaddrs()[dev]
            self._proto = []

            if AF_INET in iface_addrs.keys():
                self._src_ip = map(lambda x: inet_pton(AF_INET, x['addr']),
                                   iface_addrs[AF_INET])
                self._proto.append(NLPIDS["IP"])
            else:
                self._src_ip = None

            if AF_INET6 in iface_addrs.keys():
                self._src_ip6 = [ inet_pton(AF_INET6, x['addr'])
                                      for x in iface_addrs[AF_INET6]
                                          if 'scope' in x.keys() ]
                if self._src_ip6:
                    self._proto.append(NLPIDS["IPV6"])
            else:
                self._src_ip6 = None

            if not self._proto:
                raise NoIPAddrExc

        self._src_mac   = self._sockname[-1]
        self._area_addr = area_addr

        if src_id:
            self._src_id = src_id
        else:
            self._src_id = self._src_mac

        if lan_id:
            self._lan_id = lan_id
        else:
            self._lan_id = self._src_id + '\001'

        self._auth_passwd = passwd

        self._adjs  = { }
        self._lsps  = { }
        self._rcvd  = ""
        self._mrtd  = None
        self._dump_mrtd = 0

    def __repr__(self):

        ret = "Passive ISIS speaker, version %s:\n" % VERSION
        ret +="\tSrc MAC: %s\n" % str2hex(self._src_mac)

        if self._src_ip:
            ret += "\tSrc IP(s): %s\n" % `map(lambda x: inet_ntop(AF_INET, x), self._src_ip)`

        if self._src_ip6:
            ret += "\tSrc IPv6(s): %s\n" % `map(lambda x: inet_ntop(AF_INET6, x), self._src_ip6)`

        ret += "\tArea address: %s\n" % str2hex(self._area_addr)
        ret += "\tSrc ID: %s\n" % str2hex(self._src_id)
        ret += "\tLAN ID: %s\n" % str2hex(self._lan_id)
        ret += "\tAdjs: %s" % `self._adjs`

        return ret

    def close(self):

        self._sock.close()
        self._mrtd.close()

    #---------------------------------------------------------------------------

    def recvMsg(self, verbose=1, level=0):

        self._rcvd = self._sock.recv(RCV_BUF_SZ)
        (src_mac, dst_mac, length, dsap, ssap, ctrl) = parseMacHdr(self._rcvd)

        if verbose > 2:
            print "%srecvMsg: recv: len=%d%s" %\
                  (level*INDENT,
                   len(self._rcvd), prthex((level+1)*INDENT, self._rcvd))

        if verbose > 1:
            print "%srecvMsg: src: %s\n         dst: %s" %\
                  (level*INDENT, str2hex(src_mac), str2hex(dst_mac))
            print "         len: %d" % (length, )
            print "         dsap: %#0.2x, ssap: %#0.2x, ctl: %#0.2x" %\
                  (dsap, ssap, ctrl)

        return (len(self._rcvd), self._rcvd)

    def sendMsg(self, pkt, verbose=1, level=0):

        (src_mac, dst_mac, length, dsap, ssap, ctrl) = parseMacHdr(pkt)
        (nlpid, hdr_len, ver_proto_id, resvd,
         msg_type, ver, eco, user_eco) = parseIsisHdr(pkt[MAC_HDR_LEN:])

        if self._dump_mrtd == 1:
            self._mrtd.writeIsisMsg(msg_type, len(pkt), pkt)

        elif self._dump_mrtd == 2:
            self._mrtd.writeIsis2Msg(msg_type, len(pkt), pkt)

        if verbose > 2:
            print "%ssendMsg: send: len=%d%s" %\
                  (level*INDENT, len(pkt), prthex((level+1)*INDENT, pkt))

        if verbose > 1:
            print "%ssendMsg: src: %s\n         dst: %s" %\
                  (level*INDENT, str2hex(src_mac), str2hex(dst_mac))
            print "         len: %d" % (length, )
            print "         dsap: %#0.2x, ssap: %#0.2x, ctl: %#0.2x" %\
                  (dsap, ssap, ctrl)

        if verbose > 0:
            parseIsisMsg(len(pkt), pkt, verbose, level)

        if len(pkt) <= MAC_PKT_LEN:
            self._sock.send(pkt)

    def parseMsg(self, verbose=1, level=0):

        try:
            (msg_len, msg) = self.recvMsg(verbose, level)

        except (LLCExc):
            if verbose > 1:
                print "[ *** Non ISIS frame received *** ]"
            return

        (nlpid, hdr_len, ver_proto_id, resvd,
         msg_type, ver, eco, user_eco) = parseIsisHdr(msg[MAC_HDR_LEN:])

        if self._dump_mrtd == 1:
            self._mrtd.writeIsisMsg(msg_type, msg_len, msg)

        elif self._dump_mrtd == 2:
            self._mrtd.writeIsis2Msg(msg_type, msg_len, msg)

        if verbose > 2:
            print "%sparseMsg: len=%d%s" %\
                  (level*INDENT, msg_len, prthex((level+1)*INDENT, msg))

        rv = parseIsisMsg(msg_len, msg, verbose, level)
        self.processFsm(rv, verbose, level)

        return rv

    #---------------------------------------------------------------------------

    def mkMacHdr(self, dst_mac, src_mac, length = ISIS_PKT_LEN):

        hdr = struct.pack(">6s 6s H 3B ", dst_mac, src_mac, length,
                          ISIS_LLC_HDR[0], ISIS_LLC_HDR[1], ISIS_LLC_HDR[2])
        return hdr

    def mkIsisHdr(self, msg_type, hdr_len):

        nlpid = NLPIDS["ISIS"]
        ret   = struct.pack("8B", nlpid, hdr_len, Isis._version_proto_id,
                            0, msg_type, Isis._version, 0, 0)
        return ret

    def mkIshHdr(self, circuit, src_id, holdtimer, pdu_len, prio, lan_id):

        ret = struct.pack(">B 6s H H B 7s",
                          circuit, src_id, holdtimer, pdu_len, prio, lan_id)
        return ret

    def mkPPIshHdr(self, circuit, src_id, holdtimer, pdu_len, local_circuit_id):

        ret = struct.pack(">B 6s H H B",
                          circuit, src_id, holdtimer, pdu_len, local_circuit_id)
        return ret

    def mkPsnHdr(self, pdu_len, src_id):

        ret = struct.pack(">H 6s B", pdu_len, src_id, 0)
        return ret

    def mkVLenField(self, ftype_str, values=None):

        fval = ""
        ftype = VLEN_FIELDS[ftype_str]

        if   ftype == VLEN_FIELDS["AreaAddress"]:
            for entry in values:
                fval += struct.pack("B %ds" % len(entry), len(entry), entry)

        elif ftype == VLEN_FIELDS["LSPEntries"]:
            for entry in values:
                fval += struct.pack(">H 6sBB L H", entry[0], entry[1][0],
                              entry[1][1], entry[1][2], entry[2], entry[3])

        elif ftype == VLEN_FIELDS["Authentication"]:
            fval = struct.pack("B %ds" % len(values[1]), values[0], values[1])

        elif ftype == VLEN_FIELDS["ProtoSupported"]:
            for entry in values:
                fval += struct.pack("B", entry)

        elif ftype == VLEN_FIELDS["IPIfAddr"]:
            for entry in values:
                fval += struct.pack(">4s", entry)

        elif ftype == VLEN_FIELDS["IPv6IfAddr"]:
            for entry in values:
                fval += struct.pack(">16s", entry)

        elif ftype == VLEN_FIELDS["IIHIISNeighbor"]:
            for entry in values:
                fval += struct.pack("6s", entry)

        elif ftype == VLEN_FIELDS["MultipleTopologies"]:
            for entry in values:
                fval += struct.pack(">H", entry)

        elif ftype == VLEN_FIELDS["ThreeWayHello"]:
            fval = struct.pack("B", values)

        else:
            raise VLenFieldExc("undefined type '%s'" % ftype_str)

        flen = len(fval)
        if flen > 255:
            raise VLenFieldExc("invalid length %d" % flen)

        fhdr = struct.pack("2B", ftype, flen)

        return fhdr + fval

    def mkIsh(self, ln, lan_id, holdtimer):

        isns = []
        if ln == 1:
            dst_mac = AllL1ISs
            for adj in self._adjs.keys():
                if self._adjs[adj].has_key(1):
                    isns.append(str2mac(adj))

            msg_type = MSG_TYPES["L1LANHello"]

        elif ln == 2:
            dst_mac = AllL2ISs
            for adj in self._adjs.keys():
                if self._adjs[adj].has_key(2):
                    isns.append(str2mac(adj))

            msg_type = MSG_TYPES["L2LANHello"]

        ish = self.mkMacHdr(dst_mac, self._src_mac)
        ish = ish + self.mkIsisHdr(msg_type, ISIS_HDR_LEN + ISIS_HELLO_HDR_LEN)

        prio = 0 # we don't ever want to be elected Designated System
        ish  = ish + self.mkIshHdr(CIRCUIT_TYPES["L1L2Circuit"], self._src_id,
                             holdtimer, ISIS_PDU_LEN, prio, lan_id)

        if self._auth_passwd:
            ish += self.mkVLenField("Authentication", (1, self._auth_passwd))

        ish = ish + self.mkVLenField("ProtoSupported", self._proto)

        ish = ish + self.mkVLenField("AreaAddress", (self._area_addr,))

        if self._src_ip:
            ish = ish + self.mkVLenField("IPIfAddr", self._src_ip)
        if self._src_ip6:
            ish = ish + self.mkVLenField("IPv6IfAddr", self._src_ip6)

        ish = ish + self.mkVLenField("MultipleTopologies",
              (MTID["IPv4 routing topology"], MTID["IPv6 routing topology"]))

        if len(isns) > 0:
            ish = ish + self.mkVLenField("IIHIISNeighbor", isns)
        ish  = padPkt(MAC_PKT_LEN, ish)

        return ish

    def mkPPIsh(self, dst_mac, holdtimer, local_circuit_id, state):

        ish = self.mkMacHdr(dst_mac, self._src_mac)
        ish = ish + self.mkIsisHdr(MSG_TYPES["PPHello"], ISIS_HDR_LEN + ISIS_PP_HELLO_HDR_LEN)
        ish = ish + self.mkPPIshHdr(CIRCUIT_TYPES["L1L2Circuit"], self._src_id,
                             holdtimer, ISIS_PDU_LEN, local_circuit_id)

        if self._auth_passwd:
            ish += self.mkVLenField("Authentication", (1, self._auth_passwd))

        ish += self.mkVLenField("ThreeWayHello", state)

        ish = ish + self.mkVLenField("ProtoSupported", self._proto)
        
        ish = ish + self.mkVLenField("AreaAddress", (self._area_addr,))

        if self._src_ip:
            ish = ish + self.mkVLenField("IPIfAddr", self._src_ip)
        if self._src_ip6:
            ish = ish + self.mkVLenField("IPv6IfAddr", self._src_ip6)

        ish  = padPkt(MAC_PKT_LEN, ish)

        return ish

    def mkPsn(self, ln, dst_mac, lsp_entries):

        if ln == 1:
            msg_type = MSG_TYPES["L1PSN"]

        elif ln == 2:
            msg_type = MSG_TYPES["L2PSN"]

        else:
            raise PsnTypeExc

        hdr_len = ISIS_HDR_LEN + ISIS_PSN_HDR_LEN

        vfields = ""

        if self._auth_passwd:
            vfields += self.mkVLenField("Authentication", (1, self._auth_passwd))

        for i in range(int((len(lsp_entries)+14) / 15)):
            vfields += self.mkVLenField("LSPEntries",
                          lsp_entries[(i*15):min((i+1)*15,len(lsp_entries))])

        psn = self.mkMacHdr(dst_mac, self._src_mac, 3 + hdr_len + len(vfields))
        psn += self.mkIsisHdr(msg_type, hdr_len)
        psn += self.mkPsnHdr(hdr_len + len(vfields), self._src_id)
        psn += vfields

        return psn

    ############################################################################

    def processFsm(self, rv, verbose=1, level=0):

        src_mac = rv["H"]["SRC_MAC"]
        msg_type = rv["T"]

        smac = str2hex(src_mac)
        if not self._adjs.has_key(smac):
            self._adjs[smac] = { }

        if msg_type in (MSG_TYPES["L1LANHello"], MSG_TYPES["L2LANHello"]):

            lan_id = rv["V"]["LAN_ID"]

            k = msg_type - 14 # L1 or L2?
            if not self._adjs[smac].has_key(k):
                # new adjacency
                adj = Isis.Adj(k, rv, self.mkIsh(k, self._lan_id, rv["V"]["HOLDTIMER"]))
                self._adjs[smac][k] = adj

            else:
                # existing adjacency
                adj = self._adjs[smac][k]
                adj._state = STATES["UP"]
                adj._tx_ish = self.mkIsh(k, lan_id, rv["V"]["HOLDTIMER"])

            adj._rtx_at = 0

        elif msg_type == MSG_TYPES["PPHello"]:

            Neighbor_local_circuit_id = rv["V"]["LOCAL_CIRCUIT_ID"]

            if VLEN_FIELDS["ThreeWayHello"] in rv["V"]["VFIELDS"]:
                rx_state = rv["V"]["VFIELDS"][VLEN_FIELDS["ThreeWayHello"]][0]["V"]["STATE"]

                if   rx_state == STATES["DOWN"]:
                    tx_state = STATES["INITIALIZING"]

                elif rx_state == STATES["INITIALIZING"]:
                    tx_state = STATES["UP"]

                elif rx_state == STATES["UP"]:
                    tx_state = STATES["UP"]

                else:
                    tx_state = STATES["DOWN"]

            else:
                tx_state = STATES["UP"]

            if not self._adjs[smac].has_key(3):
                # new adjacency
                adj = Isis.Adj(3, rv, self.mkPPIsh(src_mac, rv["V"]["HOLDTIMER"],
                                                   Neighbor_local_circuit_id,
                                                   tx_state))
                self._adjs[smac][3] = adj

            else:
                # existing adjacency
                adj = self._adjs[smac][3]
                adj._state = STATES["UP"]
                adj._tx_ish = self.mkPPIsh(src_mac, rv["V"]["HOLDTIMER"],
                                         Neighbor_local_circuit_id,
                                         tx_state)

            adj._rtx_at = 0

        elif msg_type in (MSG_TYPES["L1LSP"], MSG_TYPES["L2LSP"]):

            lifetime = rv["V"]["LIFETIME"]
            lsp_id = rv["V"]["LSP_ID"]
            seq_no = rv["V"]["SEQ_NO"]
            cksm = rv["V"]["CKSM"]

            id_str = "%s.%s-%s" %\
                (str2hex(lsp_id[0]), int2hex(lsp_id[1]), int2hex(lsp_id[2]))

            if self._lsps.has_key(id_str):
                lsp = self._lsps[id_str]
                lsp._lifetime = lifetime
                lsp._seq_no   = seq_no
                lsp._cksm     = cksm
            else:
                lsp = Isis.LSP(lsp_id, lifetime, seq_no, cksm)
                self._lsps[id_str] = lsp

            # Check whether a point-to-point adjacency exists with this host
            if self._adjs[smac].has_key(MSG_TYPES["PPHello"] - 14):

                psnp_entry = [ lifetime, lsp_id, seq_no, cksm ]

                psnp = self.mkPsn (msg_type - 17, src_mac, [ psnp_entry ])
                self.sendMsg(psnp, verbose, level)

        elif msg_type in (MSG_TYPES["L1CSN"], MSG_TYPES["L2CSN"]):

            if rv["V"]["VFIELDS"].has_key(VLEN_FIELDS["LSPEntries"]):

                psnp_entries = []

                for field in rv["V"]["VFIELDS"][VLEN_FIELDS["LSPEntries"]]:

                    for entry in field["V"]:

                        lsp_id = (entry["ID"], entry["PN"], entry["NM"])
                        seq_no = entry["SEQ_NO"]
                        cksm = entry["CKSM"]

                        id_str = "%s.%s-%s" % (str2hex(lsp_id[0]),
                                  int2hex(lsp_id[1]), int2hex(lsp_id[2]))

                        if self._lsps.has_key(id_str):
                            lsp = self._lsps[id_str]
                        else:
                            lsp = Isis.LSP(lsp_id, 0, 0, 0)
                            self._lsps[id_str] = lsp

                        if lsp._seq_no < seq_no or lsp._cksm != cksm:
                            lsp_entry = [ 0, lsp_id, 0, 0 ]
                            psnp_entries.append(lsp_entry)

                if psnp_entries:
                    psnp = self.mkPsn (msg_type - 23, src_mac, psnp_entries)
                    self.sendMsg(psnp, verbose, level)

        else:
            pass

    #---------------------------------------------------------------------------

################################################################################

if __name__ == "__main__":

    import mrtd

    #---------------------------------------------------------------------------

    verbose   = 1
    dump_mrtd = 0

    file_pfx  = mrtd.DEFAULT_FILE
    file_sz   = mrtd.DEFAULT_SIZE
    mrtd_type = None
    device    = None
    area_addr = None
    src_id    = None
    lan_id    = None
    src_ip    = None
    passwd    = None

    #---------------------------------------------------------------------------

    def usage():

        print """Usage: %s [ options ] where options are ([*] required):
        -h|--help       : Help
        -v|--verbose    : Be verbose
        -q|--quiet      : Be quiet

        -a|--area-addr  : set the area address to which this IS belongs
        -i|--ip-addr    : *** HACK *** set the IP address to advertise
        -s|--src-id     : set the source ID of this IS
        -l|--lan-id     : set the LAN ID of this IS (def: "<srcid>:01")
        -p|--cleartext-password  : set the cleartext password on this interface IIS messages

        --device        : Set the device to receive on (def: %s)

        -d|--dump       : Dump MRTd::PROTOCOL_ISIS format
        -y|--dump-isis2 : Dump MRTd::PROTOCOL_ISIS2 format
        -f|--file       : Set file prefix for MRTd dump (def: %s)
        -z|--size       : Size of output file(s) (min: %d)""" %\
            (os.path.basename(sys.argv[0]), Isis._dev_str,
             mrtd.DEFAULT_FILE, mrtd.MIN_FILE_SZ)
        sys.exit(0)

    #---------------------------------------------------------------------------

    if len(sys.argv) < 2:
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hqvVdyf:s:l:a:z:i:p:",
                                   ("help", "quiet", "verbose", "VERBOSE",
                                    "dump", "dump-isis2",
                                    "file-pfx=", "file-size=", "device=",
                                    "src-id=", "lan-id=", "area-addr=", "ip-addr=",
				    "cleartext-password="))
    except (getopt.error):
        usage()

    for (x, y) in opts:
        if x in ('-h', '--help'):
            usage()

        elif x in ('-q', '--quiet'):
            verbose = 0

        elif x in ('-v', '--verbose'):
            verbose = 2

        elif x in ('-V', '--VERBOSE'):
            verbose = 3

        elif x in ('-d', '--dump'):
            dump_mrtd = 1
            mrtd_type = mrtd.MSG_TYPES["PROTOCOL_ISIS"]

        elif x in ('-y', '--dump-isis2'):
            dump_mrtd = 2
            mrtd_type = mrtd.MSG_TYPES["PROTOCOL_ISIS2"]

        elif x in ('-f', '--file-pfx'):
            file_pfx = y

        elif x in ('--device', ):
            device = y

        elif x in ('-s', '--src-id'):
            src_id = map(lambda x: int(x, 16), string.split(y, '.'))
            src_id = struct.pack("6B",
                                 src_id[0], src_id[1], src_id[2],
                                 src_id[3], src_id[4], src_id[5])

        elif x in ('-l', '--lan-id'):
            lan_id = map(lambda x: int(x, 16), string.split(y, '.'))
            lan_id = struct.pack("7B",
                                 lan_id[0], lan_id[1], lan_id[2],
                                 lan_id[3], lan_id[4], lan_id[5], lan_id[6])

        elif x in ('-a', '--area-addr'):
            area_addr = map(lambda x: int(x, 16), string.split(y, '.'))

            # this is grim, but that's not important right now...
            area_addr_str = ""
            for i in range(len(area_addr)):
                area_addr_str = struct.pack("%ds B" % len(area_addr_str),
                                            area_addr_str, area_addr[i])
            area_addr = area_addr_str

        elif x in ('-z', '--file-size'):
            file_sz = max(string.atof(y), mrtd.MIN_FILE_SZ)

        elif x in ('-i', '--ip-addr'):
            src_ip = y

        elif x in ('-p', '--cleartext-password'):
            passwd = y

        else:
            usage()

    #---------------------------------------------------------------------------

    if not area_addr:
        usage()

    isis = Isis(area_addr, device, src_id, lan_id, src_ip, passwd)
    isis._mrtd = mrtd.Mrtd(file_pfx, "w+b", file_sz, mrtd_type, isis)
    isis._dump_mrtd = dump_mrtd
    if verbose > 1:
        print `isis`

    try:
        timeout = Isis._holdtimer - RETX_THRESH
        while 1: # main loop

            before  = time.time()
            rfds, _, _ = select.select([isis._sock], [], [], timeout)

            if rfds != []:
                # need to rx pkt(s)
                rv = isis.parseMsg(verbose, 0)

            else:
                # need to tx pkt(s) of some sort
                timeout = Isis._holdtimer - RETX_THRESH

            after   = time.time()
            elapsed = after - before

            for mac in isis._adjs.keys():
                for a in isis._adjs[mac].keys():
                    adj = isis._adjs[mac][a]
                    adj._rtx_at = adj._rtx_at - elapsed
                    if adj._rtx_at <= RETX_THRESH:
                        isis.sendMsg(adj._tx_ish, verbose, 0)
                        adj._rtx_at = adj._holdtimer
                    timeout = min(timeout, adj._rtx_at-RETX_THRESH)

    except (KeyboardInterrupt):
        isis.close()
        sys.exit(1)

################################################################################
################################################################################
