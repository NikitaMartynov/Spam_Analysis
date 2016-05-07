#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# The automation of parsing the.eml files.
# It extracts attachments, urls and attachment hashes from all the emails in the current directory
# to a pre-configured folder.
# Furthermore, it is capable of automating all the submission, pulling the reports from virustotal.
#
# usage: eml_analysis [-h] [-p] [-hvt] [-uvt] [-sfvt] [-snfvt] [-rehvt] [-reuvt]
#
#
#
# Analyses all emails by parsing and checking against virustotal.
#
# optional arguments:
#   -h, --help            show this help message and exit
#   -p, --parse           Parses all emails in current location and places all
#                         extracted urls, attachments and their hashes in the
#                         corresponding files under ./parsed_output dir.
#   -hvt, --hashestovt    Pulls reports from virustotal on all extracted file
#                         hashes. The reports are placed at
#                         ./parsed_output/attachment_hashes_vt. Prerequisite: -p
#   -uvt, --urlstovt      Pulls reports from virustotal on all extracted urls.
#                         Scans are initiated automatically for all unknown
#                         urls. The reports are placed at
#                         ./parsed_output/extracted_urls_vt.Prerequisite: -p
#   -sfvt, --scanfilesonvt
#                         Submit (scan) all the extracted files at
#                         ./parsed_output/attachments dir to (via) virus total.
#   -snfvt, --scanunknownfilesonvt
#                         Submit (scan) the unknown extracted files to (via)
#                         virus total. Prerequisite: -p, -hvt
#  -rehvt, --rehashestovt
#                        Pulls reports from virustotal on all previously
#                        unknown file hashes. The reports are placed at
#                        ./parsed_output/attachment_hashes_vt_resubmited.
#                        Prerequisite: -p, -hvt, -snfvt
#  -reuvt, --reurlstovt  Pulls reports from virustotal on all previously
#                        unknown extracted urls. The reports are placed at
#                        ./parsed_output/extracted_urls_vt_resubmited.
#                         Prerequisite: -p, -uvt
#
#
# Example of usage: eml_analysis.py -p -hvt -uvt -snfvt -reuvt -rehvt
#
#
# IMPORTANT:
# The script depends of the eml_parser module. In order to correct some url parsing heuristics mind the update in
# eml_parser update definition of url_regex_simple by substituting [^ ] on [^\s].
#
import argparse
import time
import requests
import os
import base64
from eml_parser import eml_parser

_vt_api_key = ''

# Location to save attachments, hashes, urls and intermediate files
_out_path = '/parsed_output'
_attachments_path = '/parsed_output/attachments'
_hashes_filename = 'attachment_hashes'
_vt_hashes_filename = 'attachment_hashes_vt'
_vt_unknown_hashes_filename = 'attachment_hashes_vt_unknown'
_vt_resubmited_hashes_filename = 'attachment_hashes_vt_resubmited'
_extracted_urls_filename = 'extracted_urls'
_vt_extracted_urls_filename = 'extracted_urls_vt'
_vt_unknown_extracted_urls_filename = 'extracted_urls_vt_unknown'
_vt_resubmited_extracted_urls_filename = 'extracted_urls_vt_resubmited'

_not_present_in_vt = "not present"


def rtrunc_at(s, d, n=1):
    "Returns s truncated from the right at the n'th (3rd by default) occurrence of the delimiter, d."
    return d.join(s.split(d)[:n])


def ltrunc_at(s, d, n=1):
    "Returns s truncated from the left at the n'th (3rd by default) occurrence of the delimiter, d."
    return d.join(s.split(d)[n:])


def parse():
    hashes_filename_full = os.path.join(_out_path, _hashes_filename)
    urls_filename_full = os.path.join(_out_path, _extracted_urls_filename)
    open(hashes_filename_full, 'wb').close()
    open(urls_filename_full, 'wb').close()

    # parse any URLs found in the body
    list_observed_urls = []

    for eml_filename in os.listdir('.'):
        if eml_filename.endswith('.eml'):
            eml_filename = unicode(eml_filename, "utf8").encode('utf8', 'replace')
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
                    with open(hashes_filename_full, 'a') as a_out2:
                        a_out2.write("{0:s} | {1:s} | {2:s}\n".format(a['hashes']['md5'], eml_filename, filename))

            # fetching urls
            print '\tWriting urls:', urls_filename_full
            with open(urls_filename_full, 'a') as a_out:
                for url in eml_parsed['urls']:
                    url = url.split('\r\n')[0]
                    if url.count('>') - url.count('<'):
                        url = url.rsplit('>', 1)[0]
                    if url.count(']') - url.count('['):
                        url = url.rsplit(']', 1)[0]
                    if url not in list_observed_urls:
                        list_observed_urls.append(url)
                        a_out.write("{0:s} | {1:s}\n".format(eml_filename, url))
        print


def query_report_on_hashes_from_vt():
    print 'Pulling reports for all extracted hashes from virustotal:\n'
    hashes_filename_full = os.path.join(_out_path, _hashes_filename)
    vt_hashes_filename_full = os.path.join(_out_path, _vt_hashes_filename)
    with open(hashes_filename_full, 'r') as fd:
        with open(vt_hashes_filename_full, 'wb') as fd_out:
            for line in fd.readlines():
                params = {'apikey': _vt_api_key, 'resource': rtrunc_at(line, ' | ')}
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)

                response_json = response.json()
                if response_json['response_code'] == 0:
                    print_line = "{0:s} | {1:s} | {2:s}\n".format(rtrunc_at(line, ' | '), _not_present_in_vt,
                                                                  ltrunc_at(line, ' | '))
                    print (print_line)
                    fd_out.write(print_line)
                elif response_json['response_code'] == 1:
                    print_line = "{0:s} | {1:s} {2:s} {3:s} | {4:s}\n".format(rtrunc_at(line, ' | '),
                                                                              str(response_json['positives']),
                                                                              str(response_json['total']),
                                                                              str(response_json['scan_date']),
                                                                              ltrunc_at(line, ' | '))
                    fd_out.write(print_line)
                    print print_line
                else:
                    print_line = "{0:s} unexpected response code: {1:s}".format(line,
                                                                                str(response_json['response_code']))
                    fd_out.write(print_line)
                    print print_line
                time.sleep(15)


# TODO see if make sense to refactor this func with similar
def requery_report_on_hashes_from_vt():
    print 'Pulling reports for previously unknown hashes from virustotal:\n'
    hashes_filename_full = os.path.join(_out_path, _vt_unknown_hashes_filename)  # dif here
    vt_hashes_filename_full = os.path.join(_out_path, _vt_resubmited_hashes_filename)  # dif here
    with open(hashes_filename_full, 'r') as fd:
        with open(vt_hashes_filename_full, 'w') as fd_out:
            for line in fd.readlines():
                if _not_present_in_vt not in line:  # dif here
                    continue
                params = {'apikey': _vt_api_key, 'resource': rtrunc_at(line, ' | ')}
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)

                response_json = response.json()
                if response_json['response_code'] == 0:
                    print_line = "{0:s} | {1:s} | {2:s}\n".format(rtrunc_at(line, ' | '), _not_present_in_vt,
                                                                  ltrunc_at(line, ' | '))
                    print (print_line)
                    fd_out.write(print_line)
                elif response_json['response_code'] == 1:
                    last_part = ltrunc_at(line, ' | ', 2)  # dif here
                    print_line = "{0:s} | {1:s} {2:s} {3:s} | {4:s}\n".format(rtrunc_at(line, ' | '),
                                                                              str(response_json['positives']),
                                                                              str(response_json['total']),
                                                                              str(response_json['scan_date']),
                                                                              last_part)
                    fd_out.write(print_line)
                    print print_line
                else:
                    print_line = "{0:s} unexpected response code: {1:s}".format(line,
                                                                                str(response_json['response_code']))
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
    print 'Submitting all files to virustotal:'
    for root, dirs, filenames in os.walk(_attachments_path):
        for fn in filenames:
            submit_file_to_virustotal(fn)


def get_unknown_to_vt(unsorted_filename, sorted_output_filename):
    vt_filename_full = os.path.join(_out_path, unsorted_filename)
    vt_unknown_filename_full = os.path.join(_out_path, sorted_output_filename)
    with open(vt_filename_full, 'r') as f:
        with open(vt_unknown_filename_full, 'wb') as f_out:
            for line in f.readlines():
                if _not_present_in_vt not in line:
                    continue
                f_out.write(line)


def submit_unknown_files_to_virustotal():
    print 'Submitting all unknown files to virustotal:\n'
    get_unknown_to_vt(_vt_hashes_filename, _vt_unknown_hashes_filename)
    vt_unknown_hashes_filename_full = os.path.join(_out_path, _vt_unknown_hashes_filename)
    try:
        with open(vt_unknown_hashes_filename_full, 'r') as f:
            for line in f.readlines():
                submit_file_to_virustotal(ltrunc_at(line, ' | ', 3).rstrip('\n'))
    except IOError as er:
        if er.errno == 2:
            print 'There are no unknown to virustotal file. Nothing will be submitted.'
        else:
            print er


def get_url_report_from_vt():
    print 'Pulling url reports from virustotal:\n'
    extracted_urls_filename_full = os.path.join(_out_path, _extracted_urls_filename)
    vt_extracted_urls_filename_full = os.path.join(_out_path, _vt_extracted_urls_filename)
    with open(extracted_urls_filename_full, 'r') as fd:
        with open(vt_extracted_urls_filename_full, 'wb') as fd_out:
            for line in fd.readlines():
                params = {'apikey': _vt_api_key, 'resource': ltrunc_at(line, ' | ').rstrip('\n'), 'scan': 1}
                response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)

                response_json = response.json()
                if "queued" in response_json['verbose_msg']:
                    print_line = "{0:s} | {1:s} | {2:s}\n".format(rtrunc_at(line, ' | '), _not_present_in_vt,
                                                                  ltrunc_at(line, ' | '))
                    print (print_line)
                    fd_out.write(print_line)
                elif "Scan finished" in response_json['verbose_msg']:
                    print_line = "{0:s} | {1:s} {2:s} {3:s}  | {4:s}\n".format(rtrunc_at(line, ' | '),
                                                                               str(response_json['positives']),
                                                                               str(response_json['total']),
                                                                               str(response_json['scan_date']),
                                                                               ltrunc_at(line, ' | '))
                    fd_out.write(print_line)
                    print print_line
                else:
                    print_line = "{0:s} unexpected response code: {1:s}".format(line,
                                                                                str(response_json['response_code']))
                    fd_out.write(print_line)
                    print print_line
                time.sleep(15)


# TODO see if make sense to refactor this func with similar
def get_previously_unknown_url_report_from_vt():
    print 'Pulling previously unknown url reports from virustotal:\n'
    get_unknown_to_vt(_vt_extracted_urls_filename, _vt_unknown_extracted_urls_filename)  # dif
    vt_unknown_extracted_urls_filename_full = os.path.join(_out_path, _vt_unknown_extracted_urls_filename)  # dif
    vt_resubmited_extracted_urls_filename_full = os.path.join(_out_path, _vt_resubmited_extracted_urls_filename)  # dif
    with open(vt_unknown_extracted_urls_filename_full, 'r') as fd:
        with open(vt_resubmited_extracted_urls_filename_full, 'wb') as fd_out:
            for line in fd.readlines():
                params = {'apikey': _vt_api_key, 'resource': ltrunc_at(line, ' | ', 2).rstrip('\n'), 'scan': 1}  # dif
                response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)

                response_json = response.json()
                if "queued" in response_json['verbose_msg']:
                    print_line = "{0:s} | {1:s} | {2:s}\n".format(rtrunc_at(line, ' | '), _not_present_in_vt,
                                                                  ltrunc_at(line, ' | '))
                    print (print_line)
                    fd_out.write(print_line)
                elif "Scan finished" in response_json['verbose_msg']:
                    print_line = "{0:s} | {1:s} {2:s} {3:s} | {4:s}\n".format(rtrunc_at(line, ' | '),
                                                                              str(response_json['positives']),
                                                                              str(response_json['total']),
                                                                              str(response_json['scan_date']),
                                                                              ltrunc_at(line, ' | ', 2))  # dif
                    fd_out.write(print_line)
                    print print_line
                else:
                    print_line = "{0:s} unexpected response code: {1:s}".format(line,
                                                                                str(response_json['response_code']))
                    fd_out.write(print_line)
                    print print_line
                time.sleep(15)


def main():
    global _out_path
    global _attachments_path
    _out_path = os.getcwd() + _out_path
    _attachments_path = os.getcwd() + _attachments_path

    if not os.path.exists(_out_path):
        os.makedirs(_out_path)
    if not os.path.exists(_attachments_path):
        os.makedirs(_attachments_path)

    parser = argparse.ArgumentParser(prog='eml_analysis', description='Analyses all emails by parsing and checking '
                                                                      'against virustotal.',
                                     epilog='Example of usage: eml_analysis.py -p -hvt  -uvt -snfvt  -reuvt -rehvt')
    parser.add_argument('-p', '--parse', action="store_true", default=False,
                        help="Parses all emails in current location and places all extracted urls, attachments and "
                             "their hashes in the corresponding files under ./parsed_output dir.")
    parser.add_argument('-hvt', '--hashestovt', action="store_true", default=False,
                        help="Pulls reports from virustotal on all extracted file hashes. The reports are placed at "
                             "./parsed_output/attachment_hashes_vt. Prerequisite: -p")
    parser.add_argument('-uvt', '--urlstovt', action="store_true", default=False,
                        help="Pulls reports from virustotal on all extracted urls. Scans are initiated automatically "
                             "for all unknown urls. The reports are placed at ./parsed_output/extracted_urls_vt."
                             "Prerequisite: -p")
    parser.add_argument('-sfvt', '--scanfilesonvt', action="store_true", default=False,
                        help="Submit (scan) all the extracted files at ./parsed_output/attachments dir "
                             "to (via) virus total.")
    parser.add_argument('-snfvt', '--scanunknownfilesonvt', action="store_true", default=False,
                        help="Submit (scan) the unknown extracted files to (via) virus total. Prerequisite: -p, -hvt")
    parser.add_argument('-rehvt', '--rehashestovt', action="store_true", default=False,
                        help="Pulls reports from virustotal on all previously unknown file hashes. The reports are "
                             "placed at ./parsed_output/attachment_hashes_vt_resubmited. Prerequisite: -p, -hvt, -snfvt")
    parser.add_argument('-reuvt', '--reurlstovt', action="store_true", default=False,
                        help="Pulls reports from virustotal on all previously unknown extracted urls. The reports are "
                             "placed at ./parsed_output/extracted_urls_vt_resubmited. Prerequisite: -p, -uvt")

    args = parser.parse_args()
    if bool(args.parse):
        parse()
    if bool(args.hashestovt):
        query_report_on_hashes_from_vt()
    if bool(args.urlstovt):
        get_url_report_from_vt()
    if bool(args.scanfilesonvt):
        submit_files_to_virustotal()
    if bool(args.scanunknownfilesonvt):
        submit_unknown_files_to_virustotal()
    if bool(args.rehashestovt):
        requery_report_on_hashes_from_vt()
    if bool(args.reurlstovt):
        get_previously_unknown_url_report_from_vt()


if __name__ == "__main__":
    main()
