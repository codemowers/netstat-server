#!/usr/bin/env python3
import asyncio
import collections
import struct
import socket
import re
import os
from cachetools import TTLCache
from sanic import Sanic
from sanic.response import json
from prometheus_client import Gauge, Histogram
from sanic_prometheus import monitor

INTERVAL = int(os.getenv("INTERVAL", "10"))
TTL = int(os.getenv("TTL", "60"))

gauge_host_connections = Gauge("netstat_server_host_connection_count",
    "Host connection count",
    ["state"])
gauge_container_connections = Gauge("netstat_server_container_connection_count",
    "Container connection count",
    ["uid", "state"])
histogram_duration = Histogram("netstat_server_scrape_duration_seconds",
    "Latency histogram")

connections = TTLCache(maxsize=100000, ttl=TTL)
listening = TTLCache(maxsize=1000000, ttl=TTL)

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


def parse_cgroup(first_line):
    _, remainder = first_line.rsplit("/", 1)

    m = re.match(r"crio\-([0-9a-z]{64})\.scope", remainder)
    if m:
        return "cri-o://%s" % m.groups()

    m = re.match(r"cri\-containerd\-([0-9a-z]{64})\.scope", remainder)
    if m:
        return "containerd://%s" % m.groups()


@app.get("/export")
async def export(request):
    z = {
        "connections": [(k[0], k[1], k[2], k[3], k[4], v) for k, v in connections.items()],
        "listening": [(k[0], k[1], k[2]) for k, v in listening.items()],
    }
    return json(z)


@histogram_duration.time()
async def poll_proc():
    prev_labels = set()
    used_labels = set()
    for j in os.listdir(PATH_PROCFS):
        await asyncio.sleep(0)
        try:
            pid = int(j)
        except ValueError:
            continue
        try:
            with open(os.path.join(PATH_PROCFS, "%d/cgroup" % pid), "r") as fh:
                cid = parse_cgroup(fh.readline().strip())
        except FileNotFoundError:
            cid = None

        counts = collections.Counter()
        for proto in ("tcp", "udp"):
            try:
                with open(os.path.join(PATH_PROCFS, "%d/net/%s" % (pid, proto)), "r") as fh:
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
                        if raddr == "0.0.0.0":
                            assert state in ("LISTEN", "CLOSE")
                            listening[(cid, lport, proto.upper())] = 1
                            continue
                        connections[(cid, lport, raddr, rport, proto.upper())] = state
                        counts[(cid, state)] += 1

            except FileNotFoundError:
                # TODO: no network stack at all?
                continue

        used_labels = set()
        for key, value in counts.items():
            used_labels.add(key)
            prev_labels.discard(key)
            if key[0]:
                gauge_container_connections.labels(*key).set(value)
            else:
                gauge_host_connections.labels(key[1]).set(value)

        for key in prev_labels:
            if key[0]:
                gauge_container_connections.remove(*key)
            else:
                gauge_host_connections.remove(key[1])
        prev_labels = used_labels


async def poller():
    while True:
        await poll_proc()
        await asyncio.sleep(INTERVAL)


@app.listener("before_server_start")
async def setup_db(app, loop):
    loop.create_task(poller())


if __name__ == "__main__":
    monitor(app).expose_endpoint()
    app.run(host="0.0.0.0", port=3001, single_process=True, motd=False)
