from flask import Flask, abort, request, render_template, send_from_directory
import gzip
import configparser
import os
import uuid
import json
import base64
import hashlib
import subprocess
import time
import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

app = Flask(__name__)

FILE_NAME = "picc/config.conf"
if not os.path.exists("picc"):
    os.makedirs("picc")

config = configparser.ConfigParser()
shared_secret = None

# Video File Lock
lock = threading.Lock()

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


def get_videos():
    videos_list = next(os.walk('.'))[1]
    videos_list.remove("picc")
    videos_list.remove("templates")
    return videos_list


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", videos=get_videos())


@app.route("/video/<video>", methods=['GET'])
def show_video(video):
    return render_template("video.html", video=video)


@app.route("/<video>/main.mp4", methods=['GET'])
def get_video(video):
    return send_from_directory(video, "main.mp4")


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

    try:
        if not os.path.exists(video_name):
            os.mkdir(video_name)

        json_data = request.get_json()

        encrypted_png_data = json_data['image']
        aes_key = key_pair.decrypt(base64.b64decode(json_data['key'].encode("utf-8")))

        encryptor = AES.new(aes_key, AES.MODE_CFB, IV=16 * '\x00')

        compressed_png_data = encryptor.decrypt(base64.b64decode(encrypted_png_data.encode("utf-8")))

        png_data = gzip.decompress(compressed_png_data)

        time_name = str(time.time())

        file_name = "{}/{}".format(video_name, time_name)

        lock.acquire()

        temp_file = open(file_name + ".png", "wb+")
        temp_file.write(png_data)
        temp_file.close()

        subprocess.call("ffmpeg -hide_banner -f image2 -framerate 2 -i {}.png "
                        "-vcodec h264 -acodec aac -pix_fmt yuv420p -vf 'scale=trunc(iw/2)*2:trunc(ih/2)*2' "
                        "{}.mp4".format(file_name, file_name), shell=True)

        if os.path.exists("{}/main.mp4".format(video_name)):
            # Join Them
            concat_file = open("{}.txt".format(video_name + time_name), "w+")
            concat_file.write("file '" + video_name + "/main.mp4'\n")
            concat_file.write("file '" + file_name + ".mp4'")
            concat_file.close()

            subprocess.call("ffmpeg -hide_banner -y -f concat -i {}.txt -c copy {}/main.mp4"
                            .format(video_name + time_name, video_name),
                            shell=True)

            os.remove("{}.txt".format(video_name + time_name))
        else:
            os.rename(file_name + ".mp4", "{}/main.mp4".format(video_name))

        os.remove(file_name + ".png")
        if os.path.exists(file_name + ".mp4"):
            os.remove(file_name + ".mp4")

        lock.release()
        return "Success"
    except FileNotFoundError as e:
        lock.release()
        print(e)
        abort(400)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
