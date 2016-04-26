#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Simple example showing how to parse all .eml files in the current folder
# and extract any attachments to a pre-configured folder
#

import os
import base64
from eml_parser import eml_parser

# where to save attachments to
outpath = './attachments'

for eml_filename in os.listdir('.'):
    if eml_filename.endswith('.eml'):
        print 'Parsing: ', eml_filename

        eml_parsed = eml_parser.decode_email(eml_filename, include_attachment_data=True)

        # fetching attachments and their hashes
        if bool(eml_parsed['attachments']):
            hashes_filename = os.path.join(outpath, eml_filename + '-attachments_hashes')
            open(hashes_filename, 'wb').close()

            for a_id, a in eml_parsed['attachments'].items():
                if a['filename'] == '':
                    filename = a_id
                else:
                    filename = a['filename']

                filename_path = os.path.join(outpath, filename)

                print '\tWriting attachment:', filename_path
                with open(filename_path, 'wb') as a_out:
                    a_out.write(base64.b64decode(a['raw']))

                # fetching hash
                print '\tWriting hashes:', hashes_filename
                with open(hashes_filename, 'wb+') as a_out2:
                    a_out2.write("%s %s\n" % (a['hashes']['md5'], filename))

        # fetching urls
        filename = os.path.join(outpath, eml_filename + '-urls')
        print '\tWriting urls:', filename
        with open(filename, 'wb') as a_out:
            for url in eml_parsed['urls']:
                # cut out trailer of the next line. Check if it is correct thing to do
                url = url.split('\r\n')[0]
                a_out.write("%s\n" % url)

        print
