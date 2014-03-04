#! /usr/bin/env python

from ctypes import *
from socket import AF_INET, AF_INET6, AF_PACKET, inet_ntop
from sys import platform
from mutils import int2hex

def check_cksum (data, offset, length, checksum, offset_check):

    if checksum == 0:
        return False, 'no checksum'

    available_len = len (data[offset:])
    offset_check -= offset
    if available_len < length or offset_check < 0 or offset_check + 2 > length:
        return False, 'data missing'

    init_len = length
    buff = data[offset:]
    block = offset_check / 5803

    p = 0
    c0 = 0
    c1 = 0

    while length != 0:
        seglen = length
        if block == 0:
            seglen = offset_check % 5803
            discard = True
        elif seglen > 5803:
            seglen = 5803
        block -= 1

        for i in range (seglen):
            c0 += ord (buff[p])
            c1 += c0
            p += 1

        if discard:
            p += 2
            c1 += 2 * c0
            length -= 2
            discard = False

        c0 %= 255
        c1 %= 255

        length -= seglen

    factor = (init_len - offset_check) * c0
    x = factor - c0 - c1
    #y = c1 - factor - 1
    y = c1 - factor

    if x < 0:
        x -= 1

    if y > 0:
        y += 1

    x %= 255
    y %= 255

    if x == 0:
        x = 0xFF

    if y == 0:
        y = 0x01

    result = (x << 8) | (y & 0xFF)

    if result != checksum:
        return False, 'incorrect'

    return True, 'ok'

def getifaddrs():
    
    # Source code from carnivore.it
    # Address: http://carnivore.it/2010/07/22/python_-_getifaddrs
    # License CC BY-NC-SA

    # getifaddr structs
    class ifa_ifu_u(Union):
        _fields_ = [ 
            ( "ifu_broadaddr", c_void_p ),
            ( "ifu_dstaddr",   c_void_p )  
        ]
 
 
    class ifaddrs(Structure):
        _fields_ = [
            ( "ifa_next",    c_void_p  ),
            ( "ifa_name",    c_char_p  ),
            ( "ifa_flags",   c_uint    ),
            ( "ifa_addr",    c_void_p  ),
            ( "ifa_netmask", c_void_p  ),
            ( "ifa_ifu",     ifa_ifu_u ),
            ( "ifa_data",    c_void_p  ) 
        ]
 
    # AF_UNKNOWN / generic
    if platform.startswith( "darwin" ) or platform.startswith( "freebsd" ):
        class sockaddr ( Structure ):
            _fields_ = [ 
                ("sa_len",     c_uint8 ),
                ("sa_family",  c_uint8 ),
                ("sa_data",   (c_uint8 * 14) ) ]
    else:
        class sockaddr(Structure):
            _fields_ = [
                ( "sa_family", c_uint16 ),
                ( "sa_data",   (c_uint8 * 14) ) 
            ]
 
    # AF_INET / IPv4
    class in_addr(Union):
        _fields_ = [
            ("s_addr", c_uint32),
        ]
 
    class sockaddr_in(Structure):
        _fields_ = [
            ("sin_family", c_short),
            ("sin_port",   c_ushort),
            ("sin_addr",   in_addr),
            ("sin_zero",   (c_char * 8) ), # padding
        ]
 
    # AF_INET6 / IPv6
    class in6_u(Union):
        _fields_ = [
            ("u6_addr8",  (c_uint8 * 16) ),
            ("u6_addr16", (c_uint16 * 8) ),
            ("u6_addr32", (c_uint32 * 4) )
        ]
 
    class in6_addr(Union):
        _fields_ = [
            ("in6_u", in6_u),
        ]
 
    class sockaddr_in6(Structure):
        _fields_ = [
            ("sin6_family",   c_short),
            ("sin6_port",     c_ushort),
            ("sin6_flowinfo", c_uint32),
            ("sin6_addr",     in6_addr),
            ("sin6_scope_id", c_uint32),
        ]
 
    # AF_PACKET / Linux
    class sockaddr_ll( Structure ):
        _fields_ = [
            ("sll_family",   c_uint16 ),
            ("sll_protocol", c_uint16 ),
            ("sll_ifindex",  c_uint32 ),
            ("sll_hatype",   c_uint16 ),
            ("sll_pktype",   c_uint8  ),
            ("sll_halen",    c_uint8  ),
            ("sll_addr",     (c_uint8 * 8) ) 
        ]
 
    # AF_LINK / BSD|OSX
    class sockaddr_dl( Structure ):
        _fields_ = [ 
            ("sdl_len",    c_uint8  ),
            ("sdl_family", c_uint8  ),
            ("sdl_index",  c_uint16 ),
            ("sdl_type",   c_uint8  ),
            ("sdl_nlen",   c_uint8  ),
            ("sdl_alen",   c_uint8  ),
            ("sdl_slen",   c_uint8  ),
            ("sdl_data",   (c_uint8 * 46) ) 
        ]
 
    libc = CDLL("libc.so.6")
    ptr = c_void_p(None)
    result = libc.getifaddrs(pointer(ptr))
    if result:
        return None
    ifa = ifaddrs.from_address(ptr.value)
    result = {}
 
    while ifa:
        name = ifa.ifa_name
        # name = ifa.ifa_name.decode('UTF-8') # use this for python3
 
        if name not in result:
            result[name] = {}
 
        sa = sockaddr.from_address(ifa.ifa_addr)
 
        if sa.sa_family not in result[name]:
            result[name][sa.sa_family] = []
 
        data = {}
 
        if sa.sa_family == AF_INET:
            if ifa.ifa_addr is not None:
                si = sockaddr_in.from_address(ifa.ifa_addr)
                data['addr'] = inet_ntop(si.sin_family,si.sin_addr)
            if ifa.ifa_netmask is not None:
                si = sockaddr_in.from_address(ifa.ifa_netmask)
                data['netmask'] = inet_ntop(si.sin_family,si.sin_addr)
 
        if sa.sa_family == AF_INET6:
            if ifa.ifa_addr is not None:
                si = sockaddr_in6.from_address(ifa.ifa_addr)
                data['addr'] = inet_ntop(si.sin6_family,si.sin6_addr)
                if data['addr'].startswith('fe80:'):
                    data['scope'] = si.sin6_scope_id
            if ifa.ifa_netmask is not None:
                si = sockaddr_in6.from_address(ifa.ifa_netmask)
                data['netmask'] = inet_ntop(si.sin6_family,si.sin6_addr)
 
        if sa.sa_family == AF_PACKET:
            if ifa.ifa_addr is not None:
                si = sockaddr_ll.from_address(ifa.ifa_addr)
                addr = ""
                for i in range(si.sll_halen):
                    addr += "%02x:" % si.sll_addr[i]
                addr = addr[:-1]
                data['addr'] = addr
 
        if len(data) > 0:
            result[name][sa.sa_family].append(data)
 
        if ifa.ifa_next:
            ifa = ifaddrs.from_address(ifa.ifa_next)
        else:
            break
 
    libc.freeifaddrs(ptr)
    return result
