from flask import Flask, render_template, request, jsonify

from detector.analyzer import analyze_message

from database.database import (
    init_db,
    save_scan,
    get_scan_history
)


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

# Maximum message size accepted by the analyzer
MAX_MESSAGE_LENGTH = 5000


# ============================================================
# INITIALIZE DATABASE
# ============================================================

init_db()


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


# ============================================================
# ANALYZE MESSAGE
# ============================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json(silent=True) or {}

    message = data.get("message", "").strip()

    # --------------------------------------------------------
    # Empty message
    # --------------------------------------------------------

    if not message:

        return jsonify({
            "error": "Please enter a message to analyze."
        }), 400

    # --------------------------------------------------------
    # Message length validation
    # --------------------------------------------------------

    if len(message) > MAX_MESSAGE_LENGTH:

        return jsonify({
            "error": (
                f"Message is too long. "
                f"Please keep it under {MAX_MESSAGE_LENGTH} characters."
            )
        }), 400

    # --------------------------------------------------------
    # Analyze message
    # --------------------------------------------------------

    try:

        result = analyze_message(message)

    except Exception:

        return jsonify({
            "error": (
                "The message could not be analyzed. "
                "Please try again."
            )
        }), 500

    # --------------------------------------------------------
    # Save scan
    # --------------------------------------------------------

    try:

        save_scan(
            message=message,
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            signals=result["signals"],
            recommendation=result["recommendation"]
        )

    except Exception:

        return jsonify({
            "error": (
                "The analysis completed, but the scan "
                "could not be saved."
            )
        }), 500

    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return jsonify(result)


# ============================================================
# SCAN HISTORY
# ============================================================

@app.route("/history", methods=["GET"])
def history():

    try:

        scans = get_scan_history(10)

        return jsonify({
            "scans": scans
        })

    except Exception:

        return jsonify({
            "error": "Unable to load scan history."
        }), 500


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)
