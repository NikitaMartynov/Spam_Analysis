#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# The automation of parsing the.eml files.
# It extracts attachments, urls and attachment hashes from all the emails in the current directory
# to a pre-configured folder
#
import getopt
import sys
import time
import requests
import os
import base64
from eml_parser import eml_parser

# where to save attachments to
_out_path = ''
_vt_api_key = 'w'


def parse():
    hashes_filename = os.path.join(_out_path, 'attachments_hashes')
    open(hashes_filename, 'wb').close()
    for eml_filename in os.listdir('.'):
        if eml_filename.endswith('.eml'):
            print 'Parsing: ', eml_filename

            eml_parsed = eml_parser.decode_email(eml_filename, include_attachment_data=True)

            # fetching attachments and their hashes
            if bool(eml_parsed['attachments']):
                for a_id, a in eml_parsed['attachments'].items():
                    if a['filename'] == '':
                        filename = a_id
                    else:
                        filename = a['filename']

                    filename_path = os.path.join(_out_path, filename)

                    print '\tWriting attachment:', filename_path
                    with open(filename_path, 'wb') as a_out:
                        a_out.write(base64.b64decode(a['raw']))

                    # fetching hash
                    print '\tWriting hashes:', hashes_filename
                    with open(hashes_filename, 'wb+') as a_out2:
                        a_out2.write("%s | %s | %s\n" % (a['hashes']['md5'], eml_filename, filename))

            # fetching urls
            filename = os.path.join(_out_path, eml_filename + '-extracted_urls')
            print '\tWriting urls:', filename
            with open(filename, 'wb') as a_out:
                for url in eml_parsed['urls']:
                    # cut out trailer of the next line. Check if it is correct thing to do
                    url = url.split('\r\n')[0]
                    a_out.write("%s\n" % url)
        print


def main(argv):
    global _out_path
    _out_path = os.getcwd() + '/parsed_output'
    if not os.path.exists(_out_path):
        os.makedirs(_out_path)

    try:
        opts, args = getopt.getopt(argv, "hphua", ["help", "parse", "hashes", "urls", "attachments" ])
    except getopt.GetoptError:
        # TODO insert usage function
        print 'wrong usage'
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            # TODO insert usage function
            print 'TODO insert usage function'
            sys.exit()
        elif opt in ("-p", "--parse"):
            parse()
        elif opt in ("-h", "--hashes"):
            # TODO insert hashes submission
            print 'TODO insert hashes submission'
           # submit_all_hashes_to_virustotal()


if __name__ == "__main__":
    main(sys.argv[1:])
