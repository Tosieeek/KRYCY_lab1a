import click
from datetime import datetime 
import sqlite3
import os
import pandas as pd
import re
import pyshark
import subprocess
import Evtx.Evtx as evtx
 
log_file = open('app_log.txt', 'a')
con = sqlite3.connect('events_db.sqlite')
cur = con.cursor()


cur.execute('''CREATE TABLE IF NOT EXISTS app_events (date_time DATETIME, command Varchar(255), user_id Varchar(10))''')

def file_handling(file_path, re_pattern, grep_pattern, bpf_filter):

	output = ""
    
	if (file_path.endswith('.txt') or file_path.endswith('.xml') or file_path.endswith('.json')):
		if (re_pattern != "" and grep_pattern != ""):
			output = "Two patterns instead of one."
		elif (re_pattern != ""):	
			with open(file_path,"r") as file:
				for line in file:
					if re.search(re_pattern, line):
						output += line
		elif (grep_pattern != "" ):

			output = subprocess.check_output("grep " + grep_pattern + " " + file_path,shell=True).decode("utf-8")
			output = str(output)
			
		return output

	elif (file_path.endswith('.pcap')):
		shark_cap = pyshark.FileCapture(file_path, display_filter=bpf_filter)
		for packet in shark_cap:
			output += str(packet)
			
			
		return output
		
	elif (file_path.endswith('.evtx')):
		with evtx.Evtx(file_path) as log:
			for record in log.records():
				payload = str(record.xml())
				output+=payload
		return output
	
	else:
		output = "Bad file extension. Try one of (.txt, .xml, .json, .pcap, .evtx) " 
		return output
		

def scan_file(file_path, rule):
	detection_rules = __import__('detection-rules')
	method = getattr(detection_rules, rule)
	result = method(file_path)
	return result

@click.group()
def application():
    pass



@application.command()
@click.option('--file_path', multiple=True, type=click.Path(exists = True))
@click.option('--re_pattern', default="")
@click.option('--grep_pattern', default="")
@click.option('--bpf_filter', default="")

def read_file(file_path, re_pattern, grep_pattern, bpf_filter):
	
	
	now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
	log_file.write(now + ':   ')
	
	user_id = os.getuid()
	events = (now, str(file_path), user_id)
	cur.execute("insert into app_events values (?, ?, ?)", events)
	con.commit()
	output = ""
	for pth in file_path:
		if (os.path.isfile(pth)):
			output = file_handling(pth, re_pattern, grep_pattern, bpf_filter)
			click.echo(output)
		elif(os.path.isdir(pth)):
			for root, directories, files in os.walk(pth, topdown=False):
				for name in files:
					output = file_handling(os.path.join(root, name),re_pattern, grep_pattern, bpf_filter)
					click.echo(output)
			
	con.close()
	log_file.write("\n" +" write_file: "+ str(output) + "\n\n")
	log_file.close()


@application.command()
@click.option('--file_path', multiple=True, type=click.Path(exists = True))
@click.option('--rules', multiple=True)

def detect(file_path, rules):
	now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
	log_file.write(now + ':   ')
	
	user_id = os.getuid()
	events = (now, str(file_path), user_id)
	cur.execute("insert into app_events values (?, ?, ?)", events)
	con.commit()
	output = ""
	for pth in file_path:
		if (os.path.isfile(pth)):
			for rule in rules:
				output = scan_file(pth, rule)		
				click.echo(output)
				
		elif(os.path.isdir(pth)):
			for root, directories, files in os.walk(pth, topdown=False):
				for name in files:
					for rule in rules:
						output = scan_file(os.path.join(root, name),rule)
						click.echo(output)
			
	con.close()
	log_file.write("\n" +" read_file: "+ str(output) + "\n\n")
	log_file.close()



if __name__ == "__main__":
	application()
    


