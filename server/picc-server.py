from flask import Flask, abort
import gzip
import configparser
import os
import uuid
import json

app = Flask(__name__)

FILE_NAME = "picc/config.conf"
if not os.path.exists("picc"):
    os.makedirs("picc")

config = configparser.ConfigParser()
shared_secret = None

# Initial Setup
if not os.path.isfile(FILE_NAME):
    shared_secret = str(uuid.uuid4())
    config.set(configparser.DEFAULTSECT, "shared-secret", value=shared_secret)
    config.write(open(FILE_NAME, 'w+'))
else:
    config.read(FILE_NAME)
    shared_secret = config.get(configparser.DEFAULTSECT, "shared-secret")


class VideoStitcher:
    pass


@app.route("/auth/<secret>/<public_key>", methods=['GET'])
def main_root(secret=None, public_key=None):
    if not secret or not public_key:
        abort(401)
        return
    if secret != shared_secret:
        abort(403)
        return
    pass


@app.route("/send_image", methods=['POST'])
def send_image():
    pass


if __name__ == "__main__":
    app.run()
