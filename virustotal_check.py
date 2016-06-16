#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import hashlib
import argparse
import os.path
import sys
import re
from virus_total_apis import PublicApi as VirusTotalPublicApi

API_KEY = ''


def GetReportVirusTotal(vt, MD5ToCheck):
	return  vt.get_file_report(MD5ToCheck)


def ScanFileVirusTotal(vt, fileToCheck):
	return vt.scan_file(fileToCheck, from_disk=False)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Check file againt virusTotal. Print the result and exit with the number of positives checks.')
	parser.add_argument('-f', '--file', dest='fileToCheck', required=True, help='File to check')

	args = parser.parse_args()

	if os.path.isfile(args.fileToCheck):
		f=open(args.fileToCheck)
		f_data=f.read()
		f.close()

		vt = VirusTotalPublicApi(API_KEY)

		res = GetReportVirusTotal(vt, hashlib.md5(f_data).hexdigest())

		#print json.dumps(res)

# Quote from API Documentation
# https://virustotal.com/fr/documentation/public-api/
#    response_code:
# 		if the item you searched for was not present in VirusTotal's dataset this result will be 0.
#		If the requested item is still queued for analysis it will be -2.
#		If the item was indeed present and it could be retrieved it will be 1.
# 		Any other case is detailed in the following sections.
#    verbose_msg: provides verbose information regarding the response_code property.

		# Test if the file is unknown by virusTotal
		if int(res['results']['response_code']) == 0:
			# Exit if bigger than 32Mbytes
			if len(f_data)>(32*1024*1024):
				print "The file {} is unknown but biger than 32MB. Sorry.".format(args.fileToCheck)
				sys.exit(252)
			# If not, send file to VirusTotal and continu
			res = ScanFileVirusTotal(vt, f_data)

			print res
			print json.dumps(res)
			#print res['results']['verbose_msg']

			if res['results']['verbose_msg'] == "Scan request successfully queued, come back later for the report":
				print "The file is unknown and now queued by VirusTotal. You must recall later."
				print "Response_code is : {}\nVerbose_msg is : {}".format(res['results']['response_code'], res['results']['verbose_msg'])
				sys.exit(253)
			elif res['results']['verbose_msg'] == "he requested resource is not among the finished, queued or pending scans":
				print "API limits ? You can try again later"
				print "Response_code is : {}\nVerbose_msg is : {}".format(res['results']['response_code'], res['results']['verbose_msg'])
				sys.exit(254)			
			else:
				print "Oups, error but what ???"
				print "Response_code is : {}\nVerbose_msg is : {}".format(res['results']['response_code'], res['results']['verbose_msg'])
				sys.exit(255)

		print "Tested the {}. Get {} positives results on {} ({})".format(res['results']['scan_date'], res['results']['positives'],res['results']['total'], args.fileToCheck)
		if res['results']['positives'] > 0:
			print "For details : {} ".format(res['results']['permalink'])			
		sys.exit(int(res['results']['positives']))
