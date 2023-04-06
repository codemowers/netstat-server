#!/usr/bin/env python3
import struct
import socket
import re
import os
from kubernetes_asyncio import client, config
from kubernetes_asyncio.client.api_client import ApiClient
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
    mapping = {"10.96.0.1": ("default", "kubernetes")}
    async with ApiClient() as api:
        v1 = client.CoreV1Api(api)
        for pod in (await v1.list_namespaced_pod("")).items:
            mapping[pod.status.pod_ip] = pod.metadata.namespace, pod.metadata.name

    conns = []
    hostns = os.readlink(os.path.join(PATH_PROCFS, "1/ns/net"))
    for j in os.listdir(PATH_PROCFS):
        try:
            pid = int(j)
        except ValueError:
            continue
        try:
            ns = os.readlink(os.path.join(PATH_PROCFS, "%d/ns/net" % pid))
        except FileNotFoundError:
            continue
        if ns in conns:
            continue
        if ns == hostns:
            continue
        with open(os.path.join(PATH_PROCFS, "%d/net/tcp" % pid), "rb") as fh:
            fh.readline()
            for line in fh:
                cells = re.split(r"\s+", line)
                laddr, lport = cells[2].split(b":")
                raddr, rport = cells[3].split(b":")
                state = STATES[int(cells[4], 16)]
                lport, rport = int(lport, 16), int(rport, 16)
                laddr = socket.inet_ntoa(struct.pack("<L", int(laddr, 16)))
                raddr = socket.inet_ntoa(struct.pack("<L", int(raddr, 16)))
                conns.append((laddr, lport, raddr, rport, state))

    z = {
        "connections": [],
    }
    for laddr, lport, raddr, rport, state in conns:
        if laddr.startswith("127."):
            continue
        if laddr == "0.0.0.0":
            continue
        la = {"addr": laddr, "port": lport}
        la["namespace"], la["pod"] = mapping.get(laddr)
        if la["namespace"] == "longhorn-system":
            continue
        r = {"addr": raddr, "port": rport}
        j = mapping.get(raddr)
        if j:
            r["namespace"], r["pod"] = j
        z["connections"].append({
            "state": state,
            "local": la,
            "remote": r,
        })
    return json(z)


@app.listener("before_server_start")
async def setup_db(app, loop):
    if os.getenv("KUBECONFIG"):
        await config.load_kube_config()
    else:
        config.load_incluster_config()


app.run(host="0.0.0.0", port=3001, single_process=True, motd=False)
