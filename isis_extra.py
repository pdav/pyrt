#! /usr/bin/env python

from mutils import int2hex

def check_cksum (data, offset, length, checksum, offset_check, log_error=False):

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
        if log_error:
            with open ('cksum_error.log', 'a') as logfile:
                logfile.write ('Incorrect checksum %s (%s expected)\n' %\
                        (int2hex (checksum), int2hex (result)))
        return False, 'incorrect'

    return True, 'ok'

