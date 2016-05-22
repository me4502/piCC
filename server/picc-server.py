from flask import Flask, abort, request
import gzip
import configparser
import os
import uuid
import json
import base64
import hashlib

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

app = Flask(__name__)

FILE_NAME = "picc/config.conf"
if not os.path.exists("picc"):
    os.makedirs("picc")

config = configparser.ConfigParser()
shared_secret = None

# Public/Private KeyPair Generation
print("Generating KeyPair")
key_pair = RSA.generate(2048, Random.new().read)

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


@app.route("/auth/<secret>", methods=['POST'])
def auth(secret=None):
    if not secret:
        abort(400)
        return
    if secret != shared_secret:
        abort(401)
        return

    json_data = json.loads(request.get_json())

    public_key = base64.b64decode(json_data['public_key'].encode("utf-8"))

    try:
        imported_client_key = RSA.importKey(public_key, passphrase=secret)
    except ValueError as e:
        print(e)
        abort(400)
        return

    exported_public_key = key_pair.publickey().exportKey(passphrase=secret)

    # Use an AES key, because this library doesn't support CFB over an RSA key.
    aes_key = hashlib.sha256(str(uuid.uuid4()).encode("utf-8")).digest()

    encryptor = AES.new(aes_key, AES.MODE_CFB, IV=16 * '\x00')

    encrypted_public_key = encryptor.encrypt(exported_public_key)

    encrypted_aes_key = imported_client_key.publickey().encrypt(aes_key, K=32)[0]

    output_json = {"key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
                   "response": base64.b64encode(encrypted_public_key).decode("utf-8")}

    return json.dumps(output_json)


@app.route("/send_image/<video_name>", methods=['POST'])
def send_image(video_name=None):
    if not video_name:
        abort(400)
        return

    json_data = json.loads(request.get_json())

    encrypted_png_data = json_data['image']
    aes_key = key_pair.decrypt(base64.b64decode(json_data['key'].encode("utf-8")))

    encryptor = AES.new(aes_key, AES.MODE_CFB, IV=16 * '\x00')

    compressed_png_data = encryptor.decrypt(base64.b64decode(encrypted_png_data.encode("utf-8")))

    png_data = gzip.decompress(compressed_png_data)

    # TODO do the png_data

    pass


if __name__ == "__main__":
    app.run(debug=True)
