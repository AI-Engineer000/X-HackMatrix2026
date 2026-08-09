import os
import sqlite3
import json

BASE_DIR = os.path.dirname(__file__)
DATABASE = os.path.join(BASE_DIR, "scamshield.db")


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    os.makedirs(BASE_DIR, exist_ok=True)
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            risk_score INTEGER,
            risk_level TEXT,
            signals TEXT,
            recommendation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    connection.commit()
    connection.close()


def save_scan(message, risk_score, risk_level, signals, recommendation):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO scans (
            message,
            risk_score,
            risk_level,
            signals,
            recommendation
        ) VALUES (?, ?, ?, ?, ?)
    """, (
        message,
        risk_score,
        risk_level,
        json.dumps(signals or []),
        recommendation
    ))
    connection.commit()
    connection.close()


def get_scan_history(limit=10):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT
            id,
            message,
            risk_score,
            risk_level,
            signals,
            recommendation,
            created_at
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    connection.close()

    history = []
    for row in rows:
        history.append({
            "id": row["id"],
            "message": row["message"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "signals": json.loads(row["signals"] or "[]"),
            "recommendation": row["recommendation"],
            "created_at": row["created_at"]
        })

    return history
