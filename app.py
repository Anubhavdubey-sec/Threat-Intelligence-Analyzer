from flask import Flask, render_template, request
from ioc_extractor import extract_iocs, calculate_risk

import fitz
import os
import sqlite3

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


@app.route("/", methods=["GET", "POST"])
def upload():

    if request.method == "POST":

        if "pdf" not in request.files:
            return "No file uploaded"

        file = request.files["pdf"]

        if file.filename == "":
            return "No file selected"

        filepath = os.path.join(
            app.config["UPLOAD_FOLDER"],
            file.filename
        )

        file.save(filepath)

        text = ""

        pdf = fitz.open(filepath)

        for page in pdf:
            text += page.get_text()

        pdf.close()

        iocs = extract_iocs(text)

        score, severity = calculate_risk(iocs)

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO reports
            (
                filename,
                risk_score,
                severity,
                ips,
                domains,
                urls,
                emails,
                hashes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file.filename,
                score,
                severity,
                len(iocs["ips"]),
                len(iocs["domains"]),
                len(iocs["urls"]),
                len(iocs["emails"]),
                len(iocs["hashes"])
            )
        )

        conn.commit()
        conn.close()

        return render_template(
            "report.html",
            filename=file.filename,
            score=score,
            severity=severity,
            ips=iocs["ips"],
            domains=iocs["domains"],
            urls=iocs["urls"],
            emails=iocs["emails"],
            hashes=iocs["hashes"],
            ips_count=len(iocs["ips"]),
            domains_count=len(iocs["domains"]),
            urls_count=len(iocs["urls"]),
            emails_count=len(iocs["emails"]),
            hashes_count=len(iocs["hashes"])
        )

    return render_template("upload.html")


@app.route("/history")
def history():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            filename,
            risk_score,
            severity,
            created_at
        FROM reports
        ORDER BY id DESC
    """)

    reports = cursor.fetchall()

    conn.close()

    return render_template(
        "history.html",
        reports=reports
    )


@app.route("/dashboard")
def dashboard():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM reports")
    total_reports = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM reports WHERE severity='HIGH'"
    )
    high_reports = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM reports WHERE severity='MEDIUM'"
    )
    medium_reports = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM reports WHERE severity='LOW'"
    )
    low_reports = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "dashboard.html",
        total_reports=total_reports,
        high_reports=high_reports,
        medium_reports=medium_reports,
        low_reports=low_reports
    )


@app.route("/debug")
def debug():
    return f"Template Folder: {app.template_folder}"


if __name__ == "__main__":
    app.run(debug=True)