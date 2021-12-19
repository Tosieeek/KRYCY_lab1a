import re
import Evtx.Evtx as evtx
import pyshark
import yara



def detect_words_yara(filepath):
    rule = yara.compile("Databases/words.yar")
    matches = rule.match(filepath)

    found_words = []

    if len(matches) != 0:
        for log in matches[0].strings:
            found_words.append(str(log[len(log) - 1], "utf-8"))

    print(found_words)

    if len(found_words) != 0:
        action_alert = "remote"
        action_block = False
        description = "Alert - suspicious words"
    else:
        action_alert = None
        action_block = None
        description = None

    return action_alert, action_block, description, found_words


def detect_num_of_ips_yara(filepath):
    rule = yara.compile("Databases/number_of_ips.yar")
    matches = rule.match(filepath)

    found_ips = []
    if len(matches) != 0:
        for log in matches[0].strings:
            found_ips.append(str(log[len(log) - 1], "utf-8"))
        found_ips = list(dict.fromkeys(found_ips))
    print(found_ips)

    if len(matches) != 0:
        action_alert = "remote"
        action_block = True
        description = "Alert - suspicious number of ips"
    else:
        action_alert = None
        action_block = None
        description = None
    return action_alert, action_block, description, found_ips


def detect_ip(file_path):
    condition = False
    ips = []
    found_ips = []
    with open("Databases/suspicious_ips.txt", 'r') as f:
        for line in f:
            ips.append(line.strip())

    if file_path.endswith('.txt') or file_path.endswith('.xml') or file_path.endswith('.json'):
        with open(file_path, "r") as file:
            for line in file:
                for ip in ips:
                    if re.search(ip, line):
                        condition = True
                        found_ips.append(ip)

    elif file_path.endswith('.pcap'):
        shark_cap = pyshark.FileCapture(file_path)
        output = ""
        for packet in shark_cap:
            output += str(packet)
        for ip in ips:
            if re.search(ip, output):
                condition = True
                found_ips.append(ip)

    elif file_path.endswith('.evtx'):
        with evtx.Evtx(file_path) as log:
            for record in log.records():
                payload = str(record.xml())
                for ip in ips:
                    if re.search(ip, payload):
                        condition = True
                        found_ips.append(ip)

    if condition:
        action_alert = "remote"
        action_block = True
        description = "Alert - suspicious ip"
    else:
        action_alert = None
        action_block = None
        description = None

    return action_alert, action_block, description, found_ips


def detect_words(file_path):
    condition = False
    words = []
    found_words = []
    with open("Databases/suspicious_words.txt", 'r') as f:
        for line in f:
            words.append(line.strip())

    if file_path.endswith('.txt') or file_path.endswith('.xml') or file_path.endswith('.json'):
        with open(file_path, "r") as file:
            for line in file:
                for word in words:
                    if re.search(word.lower(), line.lower()):
                        condition = True
                        found_words.append(word)

    elif file_path.endswith('.pcap'):
        shark_cap = pyshark.FileCapture(file_path)
        output = ""
        for packet in shark_cap:
            output += str(packet)
        for word in words:
            if re.search(word.lower(), output.lower()):
                condition = True
                found_words.append(word)

    elif file_path.endswith('.evtx'):
        with evtx.Evtx(file_path) as log:
            for record in log.records():
                payload = str(record.xml())
                for word in words:
                    if re.search(word.lower(), payload.lower()):
                        condition = True
                        found_words.append(word)

    if condition:
        action_alert = "remote"
        action_block = False
        description = "Alert - suspicious word"
    else:
        action_alert = None
        action_block = None
        description = None

    return action_alert, action_block, description, found_words


detect_num_of_ips_yara("test_dir/test_pcap.pcap")
