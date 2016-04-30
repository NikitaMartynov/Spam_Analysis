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
_out_path = '/parsed_output'
_vt_api_key = ''
_attachment_hashes_filename = 'attachments_hashes'


def rtrunc_at(s, d, n=1):
    "Returns s truncated from the right at the n'th (3rd by default) occurrence of the delimiter, d."
    return d.join(s.split(d)[:n])


def ltrunc_at(s, d, n=1):
    "Returns s truncated from the left at the n'th (3rd by default) occurrence of the delimiter, d."
    return d.join(s.split(d)[n:])


def parse():
    hashes_filename = os.path.join(_out_path, _attachment_hashes_filename)
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


def submit_hashes_to_virustotal():
    hashes_filename = os.path.join(_out_path, _attachment_hashes_filename)
    vt_hashes_filename = hashes_filename + '_vt'
    with open(hashes_filename, 'r') as fd:
        with open(vt_hashes_filename, 'wb') as fd_out:
            for line in fd.readlines():
                params = {'apikey': _vt_api_key, 'resource': rtrunc_at(line, ' | ')}
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)

                response_json = response.json()
                if response_json['response_code'] == 0:
                    print_line = "{0:s} | not present | {1:s}\n".format(rtrunc_at(line, ' | '), ltrunc_at(line, ' | '))
                    print (print_line)
                    fd_out.write(print_line)
                elif response_json['response_code'] == 1:
                    print_line = "{0:s} | {1:s} {2:s} {3:s} | {4:s}\n".format(rtrunc_at(line, ' | '),
                                                                              response_json['response_code'],
                                                                              response_json['positives'],
                                                                              response_json['total'],
                                                                              ltrunc_at(line, ' | '))
                    fd_out.write(print_line)
                    print print_line
                else:
                    print_line = "{0:s} unexpected response code: {1:s}".format(line, response_json['response_code'])
                    fd_out.write(print_line)
                    print print_line
                time.sleep(15)


def main(argv):
    global _out_path
    _out_path = os.getcwd() + _out_path
    if not os.path.exists(_out_path):
        os.makedirs(_out_path)

    try:
        opts, args = getopt.getopt(argv, "hpmua", ["help", "parse", "md5hashes", "urls", "attachments"])
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
        elif opt in ("-m", "--md5hashes"):
            submit_hashes_to_virustotal()


if __name__ == "__main__":
    main(sys.argv[1:])
