import picamera
import gzip
import configparser
import os
import uuid
import json
import base64
import requests
import hashlib
from io import StringIO

from PIL import Image

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

from picamera import PiCamera
from gpiozero import MotionSensor
from datetime import datetime
from time import sleep


FILE_NAME = "picc/config.conf"
if not os.path.exists("picc"):
    os.makedirs("picc")

config = configparser.ConfigParser()
shared_secret = None
server_uri = None
video_name = None

# Public/Private KeyPair Generation
print("Generating KeyPair")
key_pair = RSA.generate(2048, Random.new().read)

server_public_key = None

# Initial Setup
if not os.path.isfile(FILE_NAME):
    # Shared Secret Generation
    shared_secret = str(uuid.uuid4())
    config.set(configparser.DEFAULTSECT, "shared-secret", value="ENTER SHARED SECRET")
    config.set(configparser.DEFAULTSECT, "server-uri", value="ENTER SERVER URI")
    config.set(configparser.DEFAULTSECT, "video-name", value="ENTER VIDEO NAME")

    config.write(open(FILE_NAME, 'w+'))
    print("Generated Configuration. Please fill in values before starting program again.")
    exit(0)
else:
    config.read(FILE_NAME)
    # Load Shared Secret
    shared_secret = config.get(configparser.DEFAULTSECT, "shared-secret")
    server_uri = config.get(configparser.DEFAULTSECT, "server-uri")
    video_name = config.get(configparser.DEFAULTSECT, "video-name")


# Auth with the server
def authenticate():
    auth_data = json.dumps(
        {"public_key": base64.b64encode(key_pair.publickey().exportKey(passphrase=shared_secret)).decode("utf-8")}
    )
    auth_response = requests.post(server_uri + "/auth/" + shared_secret, json=auth_data)

    if auth_response.status_code != 200:
        print("Failed to authenticate with server! Ensure you are using the correct URI and Shared Secret. Error: " +
              str(auth_response.status_code))
        exit(-1)

    auth_response_json = auth_response.json()
    aes_key = key_pair.decrypt(base64.b64decode(auth_response_json['key'].encode("utf-8")))

    encryptor = AES.new(aes_key, AES.MODE_CFB, IV=16 * '\x00')

    global server_public_key

    server_public_key = encryptor.decrypt(base64.b64decode(auth_response_json['response'].encode("utf-8")))
    RSA.importKey(server_public_key, passphrase=shared_secret)


# Pass images to this function once they are taken. Pass this a PIL Image
def send_image(image):
    aes_key = hashlib.sha256(str(uuid.uuid4()).encode("utf-8")).digest()
    encryptor = AES.new(aes_key, AES.MODE_CFB, IV=16 * '\x00')

    output_image = StringIO()
    image.save(output_image, format="PNG")

    encrypted_image = encryptor.encrypt(gzip.compress(output_image.getvalue()))
    output_image.close()

    encrypted_aes_key = server_public_key.publickey().encrypt(aes_key, K=32)[0]

    image_data = {"key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
                  "image": base64.b64encode(encrypted_image).decode("utf-8")}

    requests.post(server_uri + "/send_image/" + video_name, json=image_data)


authenticate()

# Do the stuff with the camera and motion sensor.
def main():
    camera = PiCamera()
    pir = MotionSensor(4)

    while True:
        pir.wait_for_motion():
        while motion_detected():
                filename = datetime.now().strftime("%Y-%m-%d_%H.%M.%S.h264")
                image = camera.capture(filename,format=jpeg)
                send_image(image)
                sleep(0.2)
                
