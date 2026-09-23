from flask import Flask, render_template, request
from detector import analyze_url
import sqlite3

app = Flask(__name__)

DATABASE = "phishguard.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():

    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            result TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:

            result = analyze_url(url)

            connection = get_db_connection()

            connection.execute(
                """
                INSERT INTO scans (url, score, result)
                VALUES (?, ?, ?)
                """,
                (
                    url,
                    result["score"],
                    result["result"]
                )
            )

            connection.commit()
            connection.close()

    connection = get_db_connection()

    history = connection.execute(
        """
        SELECT * FROM scans
        ORDER BY id DESC
        """
    ).fetchall()

    total_scans = connection.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    safe_scans = connection.execute(
        "SELECT COUNT(*) FROM scans WHERE result = 'Likely Safe'"
    ).fetchone()[0]

    suspicious_scans = connection.execute(
        "SELECT COUNT(*) FROM scans WHERE result = 'Suspicious'"
    ).fetchone()[0]

    high_risk_scans = connection.execute(
        "SELECT COUNT(*) FROM scans WHERE result = 'High Risk'"
    ).fetchone()[0]

    connection.close()

    return render_template(
        "index.html",
        result=result,
        history=history,
        total_scans=total_scans,
        safe_scans=safe_scans,
        suspicious_scans=suspicious_scans,
        high_risk_scans=high_risk_scans
    )


if __name__ == "__main__":

    initialize_database()

    app.run(debug=True)