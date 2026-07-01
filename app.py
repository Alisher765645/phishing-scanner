"""Flask web frontend for Phishing Scanner.

Thin wrapper around phishing_analyzer.analyze_email(). No detection logic
lives here. No text is persisted server-side (FR: privacy).
"""

import os

from flask import Flask, jsonify, render_template, request

from phishing_analyzer import analyze_email

MAX_TEXT_LEN = 20000

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload cap


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def api_analyze():
    text = ""

    if request.content_type and "multipart/form-data" in request.content_type:
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            return jsonify({"error": "Файл не передан."}), 400
        raw = uploaded.read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")
    else:
        payload = request.get_json(silent=True) or {}
        text = payload.get("text", "")

    text = (text or "").strip()
    if not text:
        return jsonify({"error": "Пустой текст — нечего анализировать."}), 400

    result = analyze_email(text[:MAX_TEXT_LEN])
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
