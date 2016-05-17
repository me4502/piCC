from flask import Flask

app = Flask(__name__)


@app.route("/", methods=['GET'])
def main_root():
    pass


@app.route("/send_image", methods=['POST'])
def send_image():
    pass


if __name__ == "__main__":
    app.run()
