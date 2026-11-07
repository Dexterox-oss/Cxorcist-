import hashlib, os, pickle, subprocess
import requests
import yaml
from flask import Flask

app = Flask(__name__)
password = "hunter2hunter2"          # deliberately bad: hard-coded credential


def run(cmd, items=[]):               # deliberately bad: mutable default
    subprocess.run(cmd, shell=True)
    os.system("ls " + cmd)
    return eval(cmd)


def load(blob, text):
    cfg = yaml.load(text)
    obj = pickle.loads(blob)
    requests.get("https://example.com", verify=False)
    try:
        hashlib.md5(b"x")
    except:
        pass
    return cfg, obj


if __name__ == "__main__":
    app.run(debug=True)
