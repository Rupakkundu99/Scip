"""Tiny sample app that imports a few of the pinned packages (useful later for reachability)."""
import yaml
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/load")
def load():
    return str(yaml.load(request.args.get("data", ""), Loader=yaml.Loader))


@app.route("/fetch")
def fetch():
    return requests.get(request.args.get("url", "http://example.com")).text
