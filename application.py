import json
import click
from datetime import datetime
import sqlite3
import os
import pandas as pd
import re
import pyshark
import subprocess
import Evtx.Evtx as evtx
import requests
import shutil

log_file = open('Databases/app_log.txt', 'a')
con = sqlite3.connect('Databases/events_db.sqlite')
cur = con.cursor()

cur.execute(
    '''CREATE TABLE IF NOT EXISTS app_events (date_time DATETIME, command Varchar(255), user_id Varchar(10), path Varchar(255))''')


def file_handling(file_path, re_pattern, grep_pattern, bpf_filter):
    output = ""

    if file_path.endswith('.txt') or file_path.endswith('.xml') or file_path.endswith('.json'):
        if re_pattern != "" and grep_pattern != "":
            output = "Two patterns instead of one."
        elif re_pattern != "":
            with open(file_path, "r") as file:
                for line in file:
                    if re.search(re_pattern, line):
                        output += line

        elif grep_pattern != "":

            output = subprocess.check_output("grep " + grep_pattern + " " + file_path, shell=True).decode("utf-8")
            output = str(output)

        else:
            with open(file_path, "r") as file:
                for line in file:
                    output += line

        return output

    elif file_path.endswith('.pcap') or file_path.endswith('.pcapng'):
        shark_cap = pyshark.FileCapture(file_path, display_filter=bpf_filter)
        for packet in shark_cap:
            output += str(packet)

        return output

    elif file_path.endswith('.evtx'):
        with evtx.Evtx(file_path) as log:
            for record in log.records():
                payload = str(record.xml())
                output += payload
        return output

    else:
        output = "Bad file extension. Try one of (.txt, .xml, .json, .pcap, .evtx) "
        return output


def scan_file(file_path, rule):
    detection_rules = __import__('detection-rules')
    method = getattr(detection_rules, rule)
    result = method(file_path)
    return result


def process_output(output, firewall, console):
    if output[0] == "remote" and console != "":
        pload = {'action_alert': str(output[0]), 'action_block': str(output[1]), 'description': str(output[2])}
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.post(f'http://{console}/', data=json.dumps(pload), headers=headers)

    if output[1] and firewall != "":
        if output[2].find("suspicious ip") > -1 or output[2].find("suspicious number of ips") > -1 or output[2].find("untrusted ports") > -1:
            pload = {'rule': "BLOCK", 'value': str(output[3])}
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            r = requests.post(f'http://{firewall}/', data=json.dumps(pload), headers=headers)



@click.group()
def application():
    pass


@application.command()
@click.option('--file_path', multiple=True, type=click.Path(exists=True))
@click.option('--re_pattern', default="")
@click.option('--grep_pattern', default="")
@click.option('--bpf_filter', default="")
def read_file(file_path, re_pattern, grep_pattern, bpf_filter):
    now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    log_file.write(now + ':   ')

    user_id = os.getuid()
    events = (now, "read_file", user_id, str(file_path))
    cur.execute("insert into app_events values (?, ?, ?, ?)", events)
    con.commit()
    output = ""
    for pth in file_path:
        if os.path.isfile(pth):
            output = file_handling(pth, re_pattern, grep_pattern, bpf_filter)
            click.echo(output)
        elif os.path.isdir(pth):
            for root, directories, files in os.walk(pth, topdown=False):
                for name in files:
                    output = file_handling(os.path.join(root, name), re_pattern, grep_pattern, bpf_filter)
                    click.echo(output)

    con.close()
    log_file.write("\n" + " read_file: " + str(output) + "\n\n")
    log_file.close()


@application.command()
@click.option('--file_path', multiple=True, type=click.Path(exists=True))
@click.option('--rules', multiple=True)
@click.option('--firewall', multiple=False, required=False, default="", help="ip:port")
@click.option('--console', multiple=False, required=False, default="", help="ip:port")
def detect(file_path, rules, firewall, console):
    now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    log_file.write(now + ':   ' + "\n")

    user_id = os.getuid()
    events = (now, "detect", user_id, str(file_path))
    cur.execute("insert into app_events values (?, ?, ?, ?)", events)
    con.commit()
    output = ""
    for pth in file_path:
        if os.path.isfile(pth):
            for rule in rules:
                output = scan_file(pth, rule)
                if output[0] is not None:
                    log_file.write(f" detect in {pth}: " + str(output) + "\n")
                    events = (now, rule, user_id, pth)
                    cur.execute("insert into app_events values (?, ?, ?, ?)", events)
                    con.commit()
                click.echo(output)
                process_output(output, firewall, console)

        elif os.path.isdir(pth):
            for root, directories, files in os.walk(pth, topdown=False):
                for name in files:
                    for rule in rules:
                        output = scan_file(os.path.join(root, name), rule)
                        if output[0] is not None:
                            log_file.write(f" detect in {os.path.join(root, name)}: " + str(output) + "\n")
                            events = (now, rule, user_id, os.path.join(root, name))
                            cur.execute("insert into app_events values (?, ?, ?, ?)", events)
                            con.commit()
                        click.echo(output)
                        process_output(output, firewall, console)
    log_file.write("\n")
    con.close()

    log_file.close()


@application.command()
@click.option('--action', multiple=False, help="Action you want to perform (one of netconfig)")
@click.option('--agent_host', multiple=False, help="ip:port")
@click.option('--interface', multiple=False, help="Interface to capture traffic on")
@click.option('--capture_filter', default="", multiple=False, help="Capture filter")
@click.option('--timeout', multiple=False, help="Time of capturing")
@click.option('--file_number', multiple=True, help="Number of file to download")
@click.option('--command', multiple=False, help="Command to execute")
def agent(action, agent_host, interface, capture_filter, timeout, file_number, command):
    if action == 'netconfig':
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.get(f'http://{agent_host}/netconfig', headers=headers)
        result = str(r.content).replace('\\n', '\n').replace('\\t', '\t')
        click.echo(result)

    elif action == 'capture':
        pload = {"interface": interface, "filter": capture_filter, "timeout": str(timeout)}
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        response = requests.post(f'http://{agent_host}/capture', data=json.dumps(pload), headers=headers, stream=True)
        file_name = "Files_application/pcaps/" + str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ".pcap"
        if response.status_code == 200:
            with open(file_name, 'wb') as f:
                f.write(response.content)

    elif action == 'list_pcaps':
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.get(f'http://{agent_host}/list-pcaps', headers=headers)
        click.echo(r.content)

    elif action == 'list_logs':
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.get(f'http://{agent_host}/list-logs', headers=headers)
        click.echo(r.content)

    elif action == 'download_pcap':
        for file in file_number:
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            r = requests.get(f'http://{agent_host}/list-pcaps', headers=headers)
            json_str = str(r.content)
            json_str = json_str[3:-2]
            list = json_str.split(',')
            file_name = "Files_application/pcaps/" + list[int(file)-1][4:-1]

            parameters = {"nr": file}
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            response = requests.get(f'http://{agent_host}/download-pcap', params=parameters, headers=headers, stream=True)
            if response.status_code == 200:
                with open(file_name, 'wb') as f:
                    f.write(response.content)

    elif action == 'download_log':
        for file in file_number:
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            r = requests.get(f'http://{agent_host}/list-logs', headers=headers)
            json_str = str(r.content)
            json_str = json_str[3:-2]
            list = json_str.split(',')
            file_name = "Files_application/logs/" + list[int(file)-1][4:-1]

            parameters = {"nr": file}
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            response = requests.get(f'http://{agent_host}/download-log', params=parameters, headers=headers, stream=True)
            if response.status_code == 200:
                with open(file_name, 'wb') as f:
                    f.write(response.content)
    elif action == 'command':
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        payload = {"command": command}
        r = requests.post(f'http://{agent_host}/command', headers=headers, data=json.dumps(payload))
        result = str(r.content).replace('\\n', '\n').replace('\\t', '\t')
        click.echo(result)

    else:
        click.echo("Invalid action")


if __name__ == "__main__":
    application()
