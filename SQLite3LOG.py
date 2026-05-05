import time
import sqlite3
import Config


CONFIG = Config.Load_Config()
DB_LOG_FILE = CONFIG["logs"].get("alerts_db", "Suspicious_Alerts.db")


def Create_Alerts_Table():
    connection = sqlite3.connect(DB_LOG_FILE, timeout=10)
    cursor = connection.cursor()

    cursor.execute("PRAGMA journal_mode=WAL")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            source TEXT,
            event TEXT,
            file_path TEXT,
            pid TEXT,
            process_name TEXT,
            exe_path TEXT,
            reasons TEXT,
            hash_result TEXT,
            yara_result TEXT,
            loki_result TEXT
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON alerts(alert_type)")

    connection.commit()
    connection.close()


def Split_Yara_And_Loki(yara_result, loki_result):
    if loki_result:
        return yara_result, loki_result

    if not yara_result:
        return yara_result, loki_result

    parts = [
        part.strip()
        for part in yara_result.split(" | ")
        if part.strip()
    ]

    yara_parts = []
    loki_parts = []

    for part in parts:
        if part.lower().startswith("loki"):
            loki_parts.append(part)
        else:
            yara_parts.append(part)

    return " | ".join(yara_parts), " | ".join(loki_parts)


def Log_Alert(
    alert_type,
    source,
    event="",
    file_path="",
    pid="",
    process_name="",
    exe_path="",
    reasons=None,
    hash_result="",
    yara_result="",
    loki_result=""
):
    if reasons is None:
        reasons = []

    Create_Alerts_Table()

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    yara_result, loki_result = Split_Yara_And_Loki(yara_result, loki_result)

    connection = sqlite3.connect(DB_LOG_FILE, timeout=10)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            alert_type,
            source,
            event,
            file_path,
            pid,
            process_name,
            exe_path,
            reasons,
            hash_result,
            yara_result,
            loki_result
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        alert_type,
        source,
        event,
        file_path,
        str(pid),
        process_name,
        exe_path,
        " | ".join(reasons),
        hash_result,
        yara_result,
        loki_result
    ))

    connection.commit()
    connection.close()