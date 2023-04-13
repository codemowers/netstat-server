#!/usr/bin/env python3
import asyncio
import struct
import socket
import re
import os
from cachetools import TTLCache, LRUCache
from sanic import Sanic
from sanic.response import json
from scapy.all import AsyncSniffer, DNS

reverse_lookup = LRUCache(maxsize=10000)
connections = TTLCache(maxsize=100000, ttl=60)
listening = TTLCache(maxsize=1000000, ttl=60)

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


@app.get("/reverse")
async def reverse_lookup_table(request):
    return json(dict(reverse_lookup))


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
        "reverse": dict(reverse_lookup),
        "connections": [(k[0], k[1], k[2], k[3], k[4], v) for k, v in connections.items()],
        "listening": [(k[0], k[1], k[2]) for k, v in listening.items()],
    }
    return json(z)


async def poller():
    while True:
        for j in os.listdir(PATH_PROCFS):
            try:
                pid = int(j)
            except ValueError:
                continue
            try:
                with open(os.path.join(PATH_PROCFS, "%d/cgroup" % pid), "r") as fh:
                    cid = parse_cgroup(fh.readline().strip())
            except FileNotFoundError:
                # TODO: host namespace?
                continue

            try:
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
                            listening[(cid, lport, "TCP")] = 1
                            continue

                        connections[(cid, lport, raddr, rport, "TCP")] = state
            except FileNotFoundError:
                # TODO: no network stack at all?
                continue
        await asyncio.sleep(30)


def process_packet(p):
    if not p.haslayer(DNS):
        return
    if not p.an:
        return
    a_count = p[DNS].ancount
    i = a_count + 4
    while i > 4:
        try:
            answer, query, answer_type = p[0][i].rdata, p[0][i].rrname, p[0][i].type
        except AttributeError:
            continue
        i -= 1
        if answer_type != 1:
            continue
        hostname = query.decode("ascii").lower().rstrip(".")
        if hostname.endswith(".local"):
            continue
        reverse_lookup[answer] = hostname


@app.listener("before_server_start")
async def setup_db(app, loop):
    loop.create_task(poller())
    sniffer = AsyncSniffer(prn=process_packet, filter="port 53", store=False)
    sniffer.start()
    sniffer2 = AsyncSniffer(iface="lo", prn=process_packet, filter="port 53", store=False)
    sniffer2.start()

app.run(host="0.0.0.0", port=3001, single_process=True, motd=False)
