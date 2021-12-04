import re
import Evtx.Evtx as evtx 

def detect_ip(file_path):
	condition = False
	ips = []
	with open("suspicious_ips.txt", 'r') as f:
        	for line in f:
        		ips.append(line.strip())
        		
	if (file_path.endswith('.txt') or file_path.endswith('.xml') or file_path.endswith('.json')):
		with open(file_path,"r") as file:
			for line in file:
				for ip in ips:
					if re.search(ip, line):
						condition = True
						break

	elif (file_path.endswith('.pcap')):
		shark_cap = pyshark.FileCapture(file_path)
		for packet in shark_cap:
			output += str(packet)
		for ip in ips:
			if re.search(ip, output):
				condition = True
				break	
			
	
	elif (file_path.endswith('.evtx')):
		with evtx.Evtx(file_path) as log:
			for record in log.records():
				payload = str(record.xml())
				for ip in ips:
					if re.search(ip, payload):
						condition = True
						break	

	if condition==True:
		action_alert = "remote"
		action_block = True 
		description = "Alert - suspicious ip" 
	else:
		action_alert = None
		action_block = None
		description = None
	
	return action_alert, action_block, description