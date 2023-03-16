#!/usr/bin/env python3
import ecs_logging
import logging
import os
import sys
from flask import Flask, request
from flask.logging import default_handler
from prometheus_flask_exporter import PrometheusMetrics
from random import random
from time import sleep

try:
    _, greeting = sys.argv
except ValueError:
    greeting = "Hello from Python!"

app = Flask(__name__)
handler = logging.StreamHandler()
handler.setFormatter(ecs_logging.StdlibFormatter())
logging.getLogger("werkzeug").removeHandler(default_handler)
logging.getLogger("werkzeug").addHandler(handler)
app.logger.removeHandler(default_handler)
app.logger.addHandler(handler)
metrics = PrometheusMetrics(app)

@app.route('/')
def index():
    sleep(random() * 5)
    app.logger.info(greeting)
    return greeting

app.run(host='0.0.0.0', port=8000)

