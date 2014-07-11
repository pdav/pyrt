#!/usr/bin/env python2.7

## This file is part of the Python Routeing Toolkit (PyRT).
## Parse IS-IS logs.

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


import os, time, struct, getopt, sys, mrtd, pprint, ospf

from mutils import *
from mrtd import MSG_TYPES as MRT_TYPES
from isis import MSG_TYPES as ISIS_TYPES, VLEN_FIELDS as ISIS_VFIELDS

################################################################################

def parse_lsp (timestr, msg, vfields, database, requests, state, verbose):

    src_id = "%s.%s" % (str2hex (msg['LSP_ID'][0]), int2hex(msg['LSP_ID'][1]))
    lsp_id = "%s-%d" % (src_id, msg['LSP_ID'][2])

    if not vfields:
        print "[%s] Warning: Unable to retrieve TLV fields from LSP '%s' (%d)."\
                " Is the checksum correct?" % (timestr, lsp_id, msg['SEQ_NO'])

    # Retrieve hostname
    if ISIS_VFIELDS['DynamicHostname'] in vfields.keys():
        hostname = vfields[ISIS_VFIELDS['DynamicHostname']][0]['V']
    elif src_id in database.keys() and msg['LSP_ID'][2] > 0:
        hostname = database[src_id]['HOSTNAME']
    else:
        hostname = src_id


    # Requested LSP?
    if lsp_id in requests:
        requests.remove (lsp_id)

    else:
        if verbose > 1:
            print "[%s] Unrequested LSP '%s' (%d) received from '%s'" %\
                    (timestr, lsp_id, msg['SEQ_NO'], hostname)


    # Known source?
    if src_id in database.keys():

        src = database[src_id]

        # Compare hostnames
        if hostname != src['HOSTNAME']:

            if verbose > 0:
                print "[%s] LSP '%s' (%d) defines new name for host '%s': "\
                        "'%s'" % (timestr, lsp_id, msg['SEQ_NO'],
                        src['HOSTNAME'], hostname)

            src['HOSTNAME'] = hostname

        # Duplicate LSP?
        if lsp_id in src['LSP_LIST'].keys() and\
                src['LSP_LIST'][lsp_id]['SEQ_NO'] == msg['SEQ_NO'] and\
                src['LSP_LIST'][lsp_id]['CKSM'] == msg['CKSM']:

            if verbose > 1:
                print "[%s] Duplicate LSP '%s' (%d) received from '%s'" %\
                    (timestr, lsp_id, msg['SEQ_NO'], hostname)

            return database, requests, state

    else:
        src = { 'HOSTNAME': hostname, 'LSP_LIST': {} }
        database[src_id] = src


    # Add LSP in list
    if lsp_id not in src['LSP_LIST'].keys():
        src['LSP_LIST'][lsp_id] = { 'NEIGHBORS': {} }

    lsp = src['LSP_LIST'][lsp_id]
    lsp['SEQ_NO'] = msg['SEQ_NO']
    lsp['CKSM'] = msg['CKSM']


    #neighbors = lsp['NEIGHBORS']
    neighbors = {}
    lsp_nbrs = []

    # Add new neighbors or update the metric of existing ones
    if ISIS_VFIELDS['TEIISNeighbor'] in vfields.keys():

        for field in vfields[ISIS_VFIELDS['TEIISNeighbor']]:

            for neighbor in field['V']:

                nbr_id = str2hex(neighbor['NID'])
                metric = str2int(neighbor['METRIC'])

                nbr_name = database[nbr_id]['HOSTNAME']\
                        if nbr_id in database.keys() else nbr_id

                if nbr_id not in neighbors.keys():
                    neighbors[nbr_id] = []

                neighbors[nbr_id].append (metric)


    for nbr_id, metrics in neighbors.iteritems():

        nbr_name = database[nbr_id]['HOSTNAME'] if nbr_id in database.keys()\
                    else nbr_id

        if nbr_id in lsp['NEIGHBORS'].keys(): # COMMON

            new = metrics[:]
            old = lsp['NEIGHBORS'][nbr_id][:]
            for nb in metrics:
                if nb in old:
                    new.remove(nb)
                    old.remove(nb)

            if state > 0 and (new or old):
                state = 2

                if verbose > 0:
                    for nb in old:
                        print "[%s] LSP '%s' (%d) from '%s' removes a "\
                                "parallel link to '%s' with metric %d" %\
                                (timestr, lsp_id, msg['SEQ_NO'], hostname,
                                nbr_name, nb)
                    for nb in new:
                        print "[%s] LSP '%s' (%d) from '%s' adds a "\
                                "parallel link to '%s' with metric %d" %\
                                (timestr, lsp_id, msg['SEQ_NO'], hostname,
                                nbr_name, nb)

        elif state > 0: # NEW
            state = 2

            if verbose > 0:
                metric_str = ""
                for m in metrics:
                    metric_str += " %d" % m

                print "[%s] LSP '%s' (%d) from '%s' adds neighbor '%s' "\
                        "with metric(s)%s" % (timestr, lsp_id, msg['SEQ_NO'],
                        hostname, nbr_name, metric_str)


    for nbr_id, metrics in lsp['NEIGHBORS'].iteritems():

        if nbr_id not in neighbors.keys(): # OLD

            if state > 0:
                state = 2

                if verbose > 0:
                    nbr_name = database[nbr_id]['HOSTNAME']\
                            if nbr_id in database.keys() else nbr_id

                    metric_str = ""
                    for m in metrics:
                        metric_str += " %d" % m

                    print "[%s] LSP '%s' (%d) from '%s' removes neighbor '%s' "\
                        "with metric(s)%s" % (timestr, lsp_id, msg['SEQ_NO'],
                        hostname, nbr_name, metric_str)

    lsp['NEIGHBORS'] = neighbors

    return database, requests, state

#-------------------------------------------------------------------------------

def parse_psn (timestr, msg, vfields, requests, database, verbose):

    if ISIS_VFIELDS['LSPEntries'] not in vfields.keys():
        # This case should not happen
        return requests

    cnt = 0

    for field in vfields[ISIS_VFIELDS['LSPEntries']]:

        for entry in field['V']:

            src_id = "%s.%s" % (str2hex(entry['ID']), int2hex(entry['PN']))
            lsp_id = "%s-%d" % (src_id, entry['NM'])

            if lsp_id not in requests and (src_id not in database.keys() or\
                    lsp_id not in database[src_id].keys() or\
                    entry['SEQ_NO'] != database[src_id][lsp_id]['SEQ_NO'] or\
                    entry['CKSM'] != database[src_id][lsp_id]['CKSM']):

                requests.append (lsp_id)
                cnt += 1

    print "[%s] PSNP sent requesting %d LSP(s)." % (timestr, cnt)

    return requests

################################################################################

def export_database (database, filename, verbose):

    fd = open (filename, 'w')

    for src_id, src_values in database.iteritems():

        for lsp_id, lsp_values in src_values['LSP_LIST'].iteritems():

            for nbr_id, links in lsp_values['NEIGHBORS'].iteritems():

                for metric in links:

                    if nbr_id in database.keys():

                        fd.write ("%s %s %d\n" % (src_values['HOSTNAME'],
                            database[nbr_id]['HOSTNAME'], metric))

                    elif verbose > 1:
                        print "Warning: no LSP received from %s" % nbr_id

    fd.close()


################################################################################

if __name__ == "__main__":

    VERBOSE = 1
    file_pfx = "topology"

    #---------------------------------------------------------------------------

    def usage():

        print """Usage: %s [ options ] <filenames>:
        -h|--help      : Help
        -v|--verbose   : Be verbose
        -q|--quiet     : Be quiet

        -f|--file       : Set file prefix for MRTd dump (def: %s)""" %\
            (os.path.basename(sys.argv[0]),file_pfx)
        sys.exit(0)

    #---------------------------------------------------------------------------

    if len(sys.argv) < 2:
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "hqvVf:",
                                   ("help", "verbose", "VERBOSE", "quiet",
                                    "file="))
    except (getopt.error):
        usage()

    for (x, y) in opts:
        if x in ('-h', '--help'):
            usage()

        elif x in ('-q', '--quiet'):
            VERBOSE = 0

        elif x in ('-v', '--verbose'):
            VERBOSE = 2

        elif x in ('-V', '--VERBOSE'):
            VERBOSE = 3

        elif x in ('-f', '--file'):
            file_pfx = y

    filenames = args
    if not filenames:
        usage()

    #---------------------------------------------------------------------------

    state = -1
    requests = []
    database = {}

    for fn in filenames:
        cnt = 0
        try:
            mrt = mrtd.Mrtd(fn, "rb", mrtd.DEFAULT_SIZE)
            error('[ %s ] parsing...\n' % fn)
            while 1:
                msg = mrt.read()

                rv = mrt.parse(msg, VERBOSE - 1)

                if rv['T'] == MRT_TYPES['PROTOCOL_ISIS']:

                    timestr = time.ctime(rv['H']['TIME'])
                    msg_type = rv['V']['T']
                    msg = rv['V']['V']

                    vfields = msg['VFIELDS']

                    if msg_type in (ISIS_TYPES['L1PSN'], ISIS_TYPES['L2PSN']):
                        requests = parse_psn (timestr, msg, vfields,
                                        requests, database, VERBOSE)

                        if state < 0 and requests:
                            state = 0

                            if VERBOSE > 0:
                                print "Initialization phase started."

                    elif msg_type in (ISIS_TYPES['L1LSP'], ISIS_TYPES['L2LSP']):
                        database, requests, state = parse_lsp (timestr, msg,
                                vfields, database, requests, state, VERBOSE)

                        if state == 0 and not requests:
                            state = 1

                            if VERBOSE > 0:
                                print "Initialization phase completed. "\
                                        "Saving topology to " + file_pfx +\
                                        "_init.ntf"

                            export_database (database, file_pfx + "_init.ntf",
                                    VERBOSE)

                        if state == 2:
                            #export_database (database, file_pfx + "_" +\
                            #        str(rv['H']['TIME']) + ".ntf", VERBOSE)
                            state = 1

                cnt = cnt + 1
                if VERBOSE > 2: pprint.pprint(rv)

        except mrtd.EOFExc:
            error("end of file: %u messages\n" % cnt)
        except KeyboardInterrupt:
            error("interrupted!\n")

        mrt.close()

    #export_database (database, file_pfx + "_final.ntf", VERBOSE)

    sys.exit(0)

################################################################################
################################################################################
