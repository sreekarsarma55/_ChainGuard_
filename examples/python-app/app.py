"""Deliberately vulnerable example for ChainGuard.

The dependencies pinned in requirements.txt carry known CVEs on purpose.
Never deploy this.
"""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index() -> str:
    return "chainguard example"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
