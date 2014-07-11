#!/usr/bin/env python2.7

## This file is part of the Python Routeing Toolkit (PyRT).
## Filter periodic messages (e.g. IIH and CSNP) out of IS-IS logs.

## Copyright 2014 Francois Clad <fclad@unistra.fr>

## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU Lesser General Public License as published by
## the Free Software Foundation, either version 3 of the License, or (at your
## option) any later version.
## 
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
## FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
## for more details.
## 
## You should have received a copy of the GNU Lesser General Public License
## along with this program. If not, see <http://www.gnu.org/licenses/>.


import os, time, struct, getopt, sys, mrtd, ospf

from mutils import *
from mrtd import MSG_TYPES as MRT_TYPES
from isis import MSG_TYPES as ISIS_TYPES, VLEN_FIELDS as ISIS_VFIELDS

################################################################################


if __name__ == "__main__":

    VERBOSE = 0

    file_pfx  = mrtd.DEFAULT_FILE
    file_sz   = mrtd.DEFAULT_SIZE

    #---------------------------------------------------------------------------

    def usage():

        print """Usage: %s [ options ] <filenames>:
        -h|--help      : Help
        -v|--verbose   : Be verbose
        -q|--quiet     : Be quiet

        -f|--file       : Set file prefix for MRTd dump (def: %s)
        -z|--size       : Size of output file(s) (min: %d)""" %\
            (os.path.basename(sys.argv[0]), file_pfx, file_sz)
        sys.exit(0)

    #---------------------------------------------------------------------------

    if len(sys.argv) < 2:
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:z:", ("help", "file=", "size="))
    except (getopt.error):
        usage()

    for (x, y) in opts:
        if x in ('-h', '--help'):
            usage()

        elif x in ('-f', '--file'):
            file_pfx = y

        elif x in ('-z', '--file-size'):
            file_sz = max(string.atof(y), mrtd.MIN_FILE_SZ)

    filenames = args
    if not filenames:
        usage()

    #---------------------------------------------------------------------------

    new_mrt = mrtd.Mrtd(file_pfx, "w+b", file_sz, MRT_TYPES['PROTOCOL_ISIS'])

    for fn in filenames:
        cnt_read = 0
        cnt_save = 0
        try:
            mrt = mrtd.Mrtd(fn, "rb", mrtd.DEFAULT_SIZE)
            
            error('[ %s ] parsing...\n' % fn)
            while 1:
                msg = mrt.read()

                rv = mrt.parse(msg, 0)

                if rv['T'] == MRT_TYPES['PROTOCOL_ISIS']:
                    t_stamp = rv['H']['TIME']
                    isis_rv = rv['V']
                    if rv['V']['T'] in (\
                            ISIS_TYPES['L1PSN'], ISIS_TYPES['L2PSN'],
                            ISIS_TYPES['L1LSP'], ISIS_TYPES['L2LSP']):

                        new_mrt.write(msg[4] + msg[5])
                        cnt_save += 1

                cnt_read += 1

        except mrtd.EOFExc:
            error("end of file: saved %u messages out of %u\n" % (cnt_save, cnt_read))
        except KeyboardInterrupt:
            error("interrupted!\n")

        mrt.close()

    new_mrt.close()

    sys.exit(0)

################################################################################
################################################################################
