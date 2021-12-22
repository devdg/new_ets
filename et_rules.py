#!/usr/bin/python3

import pandas as pd
from datetime import datetime
import requests
import re

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
	sig_date=datetime.strptime(last_update,"%Y-%m-%dT%H:%M:%SZ").strftime("%Y_%m_%d")
	files=table[table["Name"].str.contains("rules")]["Name"].values
	get_content(fixed_files,sig_date)

get_ets()
