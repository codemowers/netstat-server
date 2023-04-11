#!/usr/bin/env python3
import struct
import socket
import re
import os
from sanic import Sanic
from sanic.response import json

app = Sanic("netstat")

STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV",
}

PATH_PROCFS = os.getenv("PATH_PROCFS", "/proc")


@app.get("/export")
async def export(request):
    z = {
        "connections": [],
        "listening": [],
    }

    for j in os.listdir(PATH_PROCFS):
        try:
            pid = int(j)
        except ValueError:
            continue
        try:
            with open(os.path.join(PATH_PROCFS, "%d/cgroup" % pid), "r") as fh:
                cgroup = fh.readline().strip()
        except FileNotFoundError:
            # TODO: host namespace?
            continue
        _, cid = cgroup.rsplit("/", 1)
        m = re.match(r"crio\-([0-9a-z]{64})\.scope", cid)
        if not m:
            continue
        cid, = m.groups()
        cid = "cri-o://%s" % cid

        with open(os.path.join(PATH_PROCFS, "%d/net/tcp" % pid), "r") as fh:
            fh.readline()
            for line in fh:
                cells = re.split(r"\s+", line.strip())
                laddr, lport = cells[1].split(":")
                raddr, rport = cells[2].split(":")
                state = STATES[int(cells[3], 16)]
                lport, rport = int(lport, 16), int(rport, 16)
                laddr = socket.inet_ntoa(struct.pack("<L", int(laddr, 16)))
                raddr = socket.inet_ntoa(struct.pack("<L", int(raddr, 16)))

                if laddr.startswith("127."):
                    continue
                if state == "LISTEN":
                    assert raddr == "0.0.0.0"
                    z["listening"].append((cid, lport, "TCP"))
                    continue

                z["connections"].append((cid, lport, raddr, rport, "TCP", state))
    return json(z)


app.run(host="0.0.0.0", port=3001, single_process=True, motd=False)
