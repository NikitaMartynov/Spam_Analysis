#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# The automation of parsing the.eml files.
# It extracts attachments, urls and attachment hashes from all the emails in the current directory
# to a pre-configured folder
#
import getopt
import argparse
import sys
import time
import requests
import os
import base64
from eml_parser import eml_parser


_vt_api_key = ''

# where to save attachments to
_out_path = '/parsed_output'
_attachments_path = '/parsed_output/attachments'
_attachment_hashes_filename = 'attachments_hashes'
_attachment_hashes_vt_filename = 'attachments_hashes_vt'
_vt_hashes_filename = 'attachments_hashes_vt'
_vt_unknown_hashes_filename = 'attachments_hashes_vt_unknown'
_vt_resubmited_hashes_filename = 'attachments_hashes_vt_resubmited'

_not_present_in_virustotal = "not present"


def rtrunc_at(s, d, n=1):
    "Returns s truncated from the right at the n'th (3rd by default) occurrence of the delimiter, d."
    return d.join(s.split(d)[:n])


def ltrunc_at(s, d, n=1):
    "Returns s truncated from the left at the n'th (3rd by default) occurrence of the delimiter, d."
    return d.join(s.split(d)[n:])


def parse():
    hashes_filename_full = os.path.join(_out_path, _attachment_hashes_filename)
    open(hashes_filename_full, 'wb').close()
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

                    filename_path = os.path.join(_attachments_path, filename)

                    print '\tWriting attachment:', filename_path
                    with open(filename_path, 'wb') as a_out:
                        a_out.write(base64.b64decode(a['raw']))

                    # fetching hash
                    print '\tWriting hashes:', hashes_filename_full
                    with open(hashes_filename_full, 'wb+') as a_out2:
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
    hashes_filename_full = os.path.join(_out_path, _attachment_hashes_filename)
    vt_hashes_filename_full = os.path.join(_out_path, _vt_hashes_filename)
    with open(hashes_filename_full, 'r') as fd:
        with open(vt_hashes_filename_full, 'wb') as fd_out:
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
                                                                              str(response_json['response_code']),
                                                                              str(response_json['positives']),
                                                                              str(response_json['total']),
                                                                              ltrunc_at(line, ' | '))
                    fd_out.write(print_line)
                    print print_line
                else:
                    print_line = "{0:s} unexpected response code: {1:s}".format(line, str(response_json['response_code']))
                    fd_out.write(print_line)
                    print print_line
                time.sleep(15)


def resubmit_hashes_to_virustotal(filename):
    hashes_filename_full = os.path.join(_out_path, filename)
    vt_hashes_filename_full = os.path.join(_out_path, _vt_resubmited_hashes_filename)
    with open(hashes_filename_full, 'r') as fd:
        with open(vt_hashes_filename_full, 'w') as fd_out:
            for line in fd.readlines():
                if _not_present_in_virustotal not in line: #dif here
                    continue
                params = {'apikey': _vt_api_key, 'resource': rtrunc_at(line, ' | ')}
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)

                response_json = response.json()
                if response_json['response_code'] == 0:
                    print_line = "{0:s} | not present | {1:s}\n".format(rtrunc_at(line, ' | '), ltrunc_at(line, ' | '))
                    print (print_line)
                    fd_out.write(print_line)
                elif response_json['response_code'] == 1:
                    last_part = ltrunc_at(line, ' | ', 2) #dif here
                    print_line = "{0:s} | {1:s} {2:s} {3:s} | {4:s}\n".format(rtrunc_at(line, ' | '),
                                                                              str(response_json['response_code']),
                                                                              str(response_json['positives']),
                                                                              str(response_json['total']),
                                                                              last_part)
                    fd_out.write(print_line)
                    print print_line
                else:
                    print_line = "{0:s} unexpected response code: {1:s}".format(line, str(response_json['response_code']))
                    fd_out.write(print_line)
                    print print_line
                time.sleep(15)


def submit_file_to_virustotal(filename):
    filename_full = os.path.join(_attachments_path, filename)
    payload = {'apikey': _vt_api_key}
    files = {'file': (filename, open(filename_full, 'rb'))}
    print "Submitting", filename,
    response = requests.post("https://www.virustotal.com/vtapi/v2/file/scan", data=payload, files=files)
    response_json = response.json()
    print response_json['md5'], response_json['verbose_msg']
    time.sleep(15)


def submit_files_to_virustotal():
    for root, dirs, filenames in os.walk(_attachments_path):
        for fn in filenames:
            submit_file_to_virustotal(fn)


def get_unknown_to_virustotal_hashes():
    vt_hashes_filename_full = os.path.join(_out_path, _vt_hashes_filename)
    vt_unknown_hashes_filename_full = os.path.join(_out_path, _vt_unknown_hashes_filename)
    with open(vt_hashes_filename_full, 'r') as f:
        with open(vt_unknown_hashes_filename_full, 'wb') as f_out:
            for line in f.readlines():
                if _not_present_in_virustotal not in line:
                    continue
                f_out.write(line)


def submit_unknown_files_to_virustotal():
    vt_unknown_hashes_filename_full = os.path.join(_out_path, _vt_unknown_hashes_filename)
    with open(vt_unknown_hashes_filename_full, 'r') as f:
        for line in f.readlines():
            submit_file_to_virustotal(ltrunc_at(line, ' | ', 3).rstrip('\n'))


def main(argv):
    global _out_path
    global _attachments_path
    _out_path = os.getcwd() + _out_path
    _attachments_path = os.getcwd() + _attachments_path

    if not os.path.exists(_out_path):
        os.makedirs(_out_path)
    if not os.path.exists(_attachments_path):
        os.makedirs(_attachments_path)

    filename_resubmit_hashes = _vt_unknown_hashes_filename
    try:
        opts, args = getopt.getopt(argv, "hpmufnr", ["help", "parse", "md5hashes", "urls", "files", "unknownfiles", "remd5hashes"])
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
        elif opt in ("-f", "--files"):
            submit_files_to_virustotal()
        elif opt in ("-n", "--unknownfiles"):
            submit_unknown_files_to_virustotal()
        elif opt in ("-r", "--remd5hashes"):
            get_unknown_to_virustotal_hashes()
            resubmit_hashes_to_virustotal(filename_resubmit_hashes)


if __name__ == "__main__":
    main(sys.argv[1:])
