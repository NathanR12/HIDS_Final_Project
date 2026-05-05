import os
import re
import time
import subprocess
import Config


CONFIG = Config.Load_Config()

LOKI_ENABLED = CONFIG["loki"]["enabled"]
LOKI_LOG_FILE = CONFIG["loki"]["log_file"]
PYTHON_EXE = CONFIG["loki"]["python_executable"]
LOKI_SCRIPT_PATH = CONFIG["loki"]["loki_script_path"]
SCAN_TIMEOUT = CONFIG["loki"]["scan_timeout_seconds"]
LOKI_SCAN_INTERVAL_DAYS = CONFIG["loki"].get("scheduled_scan_days", 30)
LOKI_LAST_SCAN_FILE = CONFIG["loki"].get("last_scan_file", "logs/loki_last_scan.txt")
MAX_ERRORS_TO_LOG = CONFIG["loki"].get("max_errors_to_log", 5)


def Log_To_File(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    with open(LOKI_LOG_FILE, "a", encoding="utf-8") as file:
        file.write("[" + timestamp + "] " + message + "\n")


def Get_Last_Loki_Scan_Time():
    if not os.path.exists(LOKI_LAST_SCAN_FILE):
        return None

    try:
        with open(LOKI_LAST_SCAN_FILE, "r", encoding="utf-8") as file:
            saved_time = file.read().strip()

        return float(saved_time)

    except Exception:
        return None


def Save_Last_Loki_Scan_Time():
    state_folder = os.path.dirname(LOKI_LAST_SCAN_FILE)

    if state_folder:
        os.makedirs(state_folder, exist_ok=True)

    with open(LOKI_LAST_SCAN_FILE, "w", encoding="utf-8") as file:
        file.write(str(time.time()))


def Is_Loki_Scan_Due():
    last_scan_time = Get_Last_Loki_Scan_Time()

    if last_scan_time is None:
        return True, "No previous Loki scan found"

    seconds_since_last_scan = time.time() - last_scan_time
    days_since_last_scan = seconds_since_last_scan / 86400

    if days_since_last_scan >= LOKI_SCAN_INTERVAL_DAYS:
        return True, "Last Loki scan was " + str(round(days_since_last_scan, 2)) + " days ago"

    days_remaining = LOKI_SCAN_INTERVAL_DAYS - days_since_last_scan

    return False, (
        "Loki scan not due yet. Last scan was "
        + str(round(days_since_last_scan, 2))
        + " days ago. Next scan in about "
        + str(round(days_remaining, 2))
        + " days"
    )


def Get_Loki_Summary(output, errors):
    alert_count = 0
    warning_count = 0
    notice_count = 0
    result = "No final Loki result found"
    error_lines = []

    combined_lines = output.splitlines() + errors.splitlines()

    for line in combined_lines:
        clean_line = line.replace("\b", "").strip()

        if not clean_line:
            continue

        results_match = re.search(
            r"Results:\s*(\d+)\s*alerts,\s*(\d+)\s*warnings,\s*(\d+)\s*notices",
            clean_line,
            re.IGNORECASE
        )

        if results_match:
            alert_count = int(results_match.group(1))
            warning_count = int(results_match.group(2))
            notice_count = int(results_match.group(3))

        if "[RESULT]" in clean_line:
            result = clean_line

        if (
            "[ERROR]" in clean_line
            or "SyntaxWarning" in clean_line
            or "DeprecationWarning" in clean_line
            or "Traceback" in clean_line
            or "yara.SyntaxError" in clean_line
        ):
            error_lines.append(clean_line)

    return alert_count, warning_count, notice_count, result, error_lines


def Check_File_Loki(src_path, force_scan=False):
    results = []

    if not LOKI_ENABLED:
        results.append("Loki scan skipped: Loki disabled in config")
        return results

    if not os.path.exists(src_path):
        results.append("Loki scan skipped: file does not exist")
        return results

    if not os.path.exists(LOKI_SCRIPT_PATH):
        results.append("Loki scan failed: loki.py not found at " + LOKI_SCRIPT_PATH)
        return results

    scan_due, scan_reason = Is_Loki_Scan_Due()

    if not scan_due and not force_scan:
        results.append("Loki scheduled scan skipped: " + scan_reason)
        Log_To_File("Loki scheduled scan skipped for " + src_path + ": " + scan_reason)
        return results

    try:
        loki_folder = os.path.dirname(LOKI_SCRIPT_PATH)

        command = [
            PYTHON_EXE,
            LOKI_SCRIPT_PATH,
            "-p",
            src_path,
            "--noprocscan"
        ]

        scan = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            cwd=loki_folder
        )

        output = scan.stdout.strip()
        errors = scan.stderr.strip()

        alert_count, warning_count, notice_count, result, error_lines = Get_Loki_Summary(output, errors)

        Log_To_File("========== LOKI SCAN SUMMARY ==========")
        Log_To_File("Target: " + src_path)
        Log_To_File("Alerts: " + str(alert_count))
        Log_To_File("Warnings: " + str(warning_count))
        Log_To_File("Notices: " + str(notice_count))
        Log_To_File("Result: " + result)

        if error_lines:
            Log_To_File("Errors:")

            for error in error_lines[:MAX_ERRORS_TO_LOG]:
                Log_To_File(error)

            if len(error_lines) > MAX_ERRORS_TO_LOG:
                Log_To_File("Additional errors hidden: " + str(len(error_lines) - MAX_ERRORS_TO_LOG))
        else:
            Log_To_File("Errors: No Loki errors reported")

        Log_To_File("=======================================")

        Save_Last_Loki_Scan_Time()

        if scan.returncode == 0:
            results.append("Loki scan completed")
        else:
            results.append("Loki scan completed with return code: " + str(scan.returncode))

        if alert_count > 0 or warning_count > 0:
            results.append("Loki result: Possible suspicious indicator found")
        else:
            results.append("Loki result: No obvious suspicious indicator found")

    except subprocess.TimeoutExpired:
        results.append("Loki scan failed: scan timed out")
        Log_To_File("Loki scan timed out for: " + src_path)

    except Exception as error:
        results.append("Loki scan failed: " + str(error))
        Log_To_File("Loki scan failed for " + src_path + ": " + str(error))

    return results
