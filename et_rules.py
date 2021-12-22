#!/usr/bin/python3

import pandas as pd
from datetime import datetime
import requests
import re
import argparse

parse = argparse.ArgumentParser()
parse.add_argument("-a","--all", help="Shows all new additions rather than the standard set", action="store_true")
parse.add_argument("-s","--search", type=str, help="When you need to find something specific")
args=parse.parse_args()

baseurl=r'https://rules.emergingthreats.net/open/snort-2.9.0/rules/'
fixed_files=["emerging-attack_response.rules","emerging-exploit.rules","emerging-malware.rules","emerging-policy.rules"]

def get_content(files,sig_date):
	for file in files:
		url=baseurl+file
		out=requests.get(url)
		result=re.findall(f'.*{sig_date}.*', out.text)
		if result:
			print(f'Matches in {file}:')
			for results in result:
				print(results)
def get_ets():
	tables=pd.read_html(baseurl)
	table=tables[0]
	last_update=table.loc[table["Name"] == "LICENSE"]["Last Modified"].values[0]
	files=table[table["Name"].str.contains("rules")]["Name"].values
	seek_for=datetime.strptime(last_update,"%Y-%m-%dT%H:%M:%SZ").strftime("%Y_%m_%d")

	if args.search:
		seek_for=args.search

	if not args.all:
		files=fixed_files

	get_content(files,seek_for)

get_ets()
