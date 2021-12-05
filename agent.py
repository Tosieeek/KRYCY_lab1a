import os
import subprocess
import pyshark
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime


# TODO zapoakowanie w model

class Capture_model(BaseModel):
    interface: str
    filter: str
    timeout: str


app = FastAPI()


def capture_live_packets(network_interface, capture_filter, timeout):
    file_name = str(datetime.now().strftime("%d-%m-%Y_%H:%M:%S")) + ".pcap"
    print(network_interface + ", " + file_name + ", " + capture_filter + ", " + str(timeout))
    file_name = "capture.pcap"
    capture = pyshark.LiveCapture(interface="enp0s3", output_file=file_name)
    capture.sniff(timeout=10)
    # capture = pyshark.LiveCapture(interface=network_interface, output_file="capture.pcap")
    # capture.sniff(timeout=timeout)


@app.get("/netconfig")
async def show_():
    output = subprocess.check_output("ip address show", shell=True).decode("utf-8")
    output = str(output)
    return output


@app.post("/capture")
async def show2_(cm: Capture_model):
    capture_live_packets(cm.interface, cm.filter, int(cm.timeout))
    # TODO wysyłanie pliku z powrotem


if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=8003)
