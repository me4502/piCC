from flask import Flask, abort, request
import gzip
import configparser
import os
import uuid
import json
import base64

from Crypto.PublicKey import RSA
from Crypto import Random

app = Flask(__name__)

FILE_NAME = "picc/config.conf"
if not os.path.exists("picc"):
    os.makedirs("picc")

config = configparser.ConfigParser()
shared_secret = None

# Public/Private KeyPair Generation
random_generator = Random.new().read
key_pair = RSA.generate(1024, random_generator)

# Initial Setup
if not os.path.isfile(FILE_NAME):
    # Shared Secret Generation
    shared_secret = str(uuid.uuid4())
    config.set(configparser.DEFAULTSECT, "shared-secret", value=shared_secret)

    config.write(open(FILE_NAME, 'w+'))
else:
    config.read(FILE_NAME)
    # Load Shared Secret
    shared_secret = config.get(configparser.DEFAULTSECT, "shared-secret")


class VideoStitcher:
    _name = None

    def __init__(self, name):
        self._name = name

    def setup(self):
        if not os.path.exists(self._name):
            os.makedirs(self._name)


@app.route("/auth/<secret>", methods=['GET'])
def auth(secret=None):
    if not secret:
        abort(400)
        return
    if secret != shared_secret:
        abort(401)
        return

    json_data = request.get_json()
    print(json_data)

    # TODO do the json_data

    public_key = None

    try:
        imported_client_key = RSA.importKey(public_key, passphrase=secret)
    except ValueError as e:
        print(e)
        abort(400)
        return

    encrypted_key = imported_client_key.encrypt(key_pair.publickey().exportKey(passphrase=secret), K=32)[0]

    output_json = {"response": base64.b64encode(encrypted_key).decode("utf-8")}

    return json.dumps(output_json)


@app.route("/send_image/<video_name>", methods=['POST'])
def send_image(video_name=None):
    if not video_name:
        abort(400)
        return

    json_data = request.get_json()
    print(json_data)

    # TODO do the json_data

    encrypted_png_data = None
    compressed_png_data = key_pair.decrypt(base64.b64decode(encrypted_png_data.encode("utf-8")))

    png_data = gzip.decompress(compressed_png_data)

    # TODO do the png_data

    pass


if __name__ == "__main__":
    app.run(debug=True)
