import os
import subprocess
from threading import Thread
import pyshark
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from fastapi.responses import FileResponse


class Capture_model(BaseModel):
    interface: str
    filter: str
    timeout: str


class Command_model(BaseModel):
    command: str


app = FastAPI()


def capture_live_packets(network_interface, capture_filter, timeout, file_name):
    capture = pyshark.LiveCapture(interface=network_interface, display_filter=capture_filter, output_file=file_name)
    capture.sniff(timeout=timeout)


@app.get("/netconfig")
async def show_():
    output = subprocess.check_output("ip address show", shell=True).decode("utf-8")
    output = str(output)
    return output


@app.post("/capture")
async def capture_(cm: Capture_model):
    file_name = "Files_agent/pcaps/" + str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ".pcap"
    thread = Thread(target=capture_live_packets, args=(cm.interface, cm.filter, int(cm.timeout), file_name))
    thread.start()
    thread.join()
    return FileResponse(file_name)


@app.get("/list-pcaps")
async def show_files_():
    path = 'Files_agent/pcaps/'
    pcap_files = []
    for root, directories, files in os.walk(path, topdown=False):
        for name in files:
            pcap_files.append(str(len(pcap_files) + 1) + ") " + name)
    return pcap_files


@app.get("/list-logs")
async def show_files_():
    path = 'Files_agent/logs/'
    log_files = []
    for root, directories, files in os.walk(path, topdown=False):
        for name in files:
            log_files.append(str(len(log_files) + 1) + ") " + name)
    return log_files


@app.get("/download-pcap")
async def download_pcap_(nr: str):
    path = 'Files_agent/pcaps/'
    file_to_send = ""
    for root, directories, files in os.walk(path, topdown=False):
        counter = 1
        for name in files:
            if counter == int(nr):
                file_to_send = os.path.join(root, name)
            counter += 1
    print(file_to_send)
    return FileResponse(file_to_send)


@app.get("/download-log")
async def download_log_(nr: str):
    path = 'Files_agent/logs/'
    file_to_send = ""
    for root, directories, files in os.walk(path, topdown=False):
        counter = 1
        for name in files:
            if counter == int(nr):
                file_to_send = os.path.join(root, name)
            counter += 1

    return FileResponse(file_to_send)


@app.post("/command")
async def command_(cm: Command_model):
    output = subprocess.check_output(cm.command, shell=True).decode("utf-8")
    output = str(output)
    return output


if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=8003)
