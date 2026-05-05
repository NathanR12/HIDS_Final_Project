import os
import sys
import sqlite3
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

import Config


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UI_RUNNER_LOG = os.path.join(BASE_DIR, "UI_Runner_Log.txt")


MONITOR_FILES = {
    "Watchdog": "Watchdog.py",
    "Windows Events": "WinEventCheck.py",
    "Process Check": "ProcessCheck.py"
}


def full_path(path):
    path = os.path.expandvars(path)

    if os.path.isabs(path):
        return path

    return os.path.join(BASE_DIR, path)


def write_ui_log(message):
    with open(UI_RUNNER_LOG, "a", encoding="utf-8", errors="replace") as file:
        file.write(message + "\n")


def read_file_tail(path, max_chars=60000):
    path = full_path(path)

    if not os.path.exists(path):
        return "File not found:\n" + path

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as file:
            file.seek(0, os.SEEK_END)
            size = file.tell()
            start = max(size - max_chars, 0)
            file.seek(start)
            text = file.read()

        if start > 0:
            return "... showing latest log data only ...\n\n" + text

        return text

    except Exception as error:
        return "Could not read file:\n" + str(error)


def read_alerts(db_path):
    db_path = full_path(db_path)

    if not os.path.exists(db_path):
        return []

    try:
        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
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
            FROM alerts
            ORDER BY id DESC
            LIMIT 500
        """)

        rows = cursor.fetchall()
        connection.close()

        return rows

    except Exception as error:
        messagebox.showerror("Database Error", str(error))
        return []


class HIDS_UI:
    def __init__(self, root):
        self.root = root
        self.root.title("HIDS Control Panel")
        self.root.geometry("1100x650")
        self.root.minsize(900, 500)

        self.config = Config.Load_Config()

        self.processes = {}
        self.log_handles = {}

        self.alerts_db = full_path(
            self.config.get("logs", {}).get("alerts_db", "Suspicious_Alerts.db")
        )

        self.log_files = self.get_log_files()

        self.build_ui()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.refresh_status()
        self.root.after(1000, self.auto_refresh_status)

    def get_log_files(self):
        logs = self.config.get("logs", {})

        return {
            "Watchdog Log": full_path(logs.get("watchdog_log", "Watchdog_Log.txt")),
            "Process Log": full_path(logs.get("process_log", "Process_Log.txt")),
            "Windows Event Log": full_path(logs.get("windows_event_log", "Windows_Event_Log.txt")),
            "UI Runner Log": UI_RUNNER_LOG,
            "Suspicious Alerts DB": self.alerts_db
        }

    def build_ui(self):
        title = ttk.Label(
            self.root,
            text="HIDS Control Panel",
            font=("Segoe UI", 18, "bold")
        )
        title.pack(anchor="w", padx=10, pady=10)

        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(button_frame, text="Start All", command=self.start_all).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Stop All", command=self.stop_all).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Refresh", command=self.refresh_everything).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Open Folder", command=self.open_folder).pack(side="left", padx=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.status_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        self.alerts_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.status_tab, text="Status")
        self.notebook.add(self.logs_tab, text="Logs")
        self.notebook.add(self.alerts_tab, text="Alerts")

        self.build_status_tab()
        self.build_logs_tab()
        self.build_alerts_tab()

        write_ui_log("Stage 7 UI loaded")

    def build_status_tab(self):
        self.status_text = ScrolledText(self.status_tab, font=("Consolas", 10))
        self.status_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_logs_tab(self):
        top = ttk.Frame(self.logs_tab)
        top.pack(fill="x", padx=10, pady=10)

        self.selected_log = tk.StringVar(value="Watchdog Log")

        self.log_dropdown = ttk.Combobox(
            top,
            textvariable=self.selected_log,
            values=list(self.log_files.keys()),
            state="readonly",
            width=30
        )
        self.log_dropdown.pack(side="left", padx=5)

        ttk.Button(top, text="Refresh Log", command=self.refresh_logs).pack(side="left", padx=5)
        ttk.Button(top, text="Clear Log", command=self.clear_selected_log).pack(side="left", padx=5)

        self.log_text = ScrolledText(self.logs_tab, font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_alerts_tab(self):
        top = ttk.Frame(self.alerts_tab)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Button(top, text="Refresh Alerts", command=self.refresh_alerts).pack(side="left", padx=5)

        self.alert_count_label = ttk.Label(top, text="Rows: 0")
        self.alert_count_label.pack(side="left", padx=10)

        table_frame = ttk.Frame(self.alerts_tab)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = (
            "Timestamp",
            "Alert Type",
            "Source",
            "Event",
            "File Path",
            "PID",
            "Process Name",
            "Executable Path",
            "Reasons",
            "Hash Result",
            "YARA Result",
            "Loki Result"
        )

        self.alert_tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        column_widths = {
            "Timestamp": 150,
            "Alert Type": 150,
            "Source": 140,
            "Event": 180,
            "File Path": 300,
            "PID": 70,
            "Process Name": 150,
            "Executable Path": 300,
            "Reasons": 350,
            "Hash Result": 300,
            "YARA Result": 300,
            "Loki Result": 300
        }

        for column in columns:
            self.alert_tree.heading(column, text=column)
            self.alert_tree.column(
                column,
                width=column_widths.get(column, 150),
                anchor="w",
                stretch=False
            )

        y_scroll = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.alert_tree.yview
        )

        x_scroll = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.alert_tree.xview
        )

        self.alert_tree.configure(
            yscrollcommand=y_scroll.set,
            xscrollcommand=x_scroll.set
        )

        self.alert_tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

    def start_all(self):
        for name, file_name in MONITOR_FILES.items():
            self.start_monitor(name, file_name)

        self.refresh_status()

    def start_monitor(self, name, file_name):
        process = self.processes.get(name)

        if process is not None and process.poll() is None:
            return

        script_path = os.path.join(BASE_DIR, file_name)

        if not os.path.exists(script_path):
            write_ui_log(name + " could not start. File missing: " + script_path)
            return

        try:
            log_handle = open(UI_RUNNER_LOG, "a", encoding="utf-8", errors="replace")
            self.log_handles[name] = log_handle

            kwargs = {
                "cwd": BASE_DIR,
                "stdout": log_handle,
                "stderr": log_handle
            }

            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

            process = subprocess.Popen(
                [sys.executable, script_path],
                **kwargs
            )

            self.processes[name] = process
            write_ui_log(name + " started with PID " + str(process.pid))

        except Exception as error:
            write_ui_log(name + " failed to start: " + str(error))

    def stop_all(self):
        for name in list(self.processes.keys()):
            self.stop_monitor(name)

        self.refresh_status()

    def stop_monitor(self, name):
        process = self.processes.get(name)

        if process is None:
            return

        try:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
                write_ui_log(name + " stopped")

        except subprocess.TimeoutExpired:
            process.kill()
            write_ui_log(name + " killed after timeout")

        except Exception as error:
            write_ui_log(name + " could not stop: " + str(error))

        handle = self.log_handles.get(name)

        if handle:
            try:
                handle.close()
            except Exception:
                pass

        self.log_handles.pop(name, None)

    def refresh_status(self):
        self.status_text.delete("1.0", tk.END)

        self.status_text.insert(tk.END, "Monitor Status\n")
        self.status_text.insert(tk.END, "==============\n\n")

        for name, file_name in MONITOR_FILES.items():
            process = self.processes.get(name)

            if process is None:
                status = "Not started"
            elif process.poll() is None:
                status = "Running | PID: " + str(process.pid)
            else:
                status = "Stopped | Exit code: " + str(process.returncode)

            self.status_text.insert(tk.END, name + ": " + status + "\n")
            self.status_text.insert(tk.END, "File: " + file_name + "\n\n")

        self.status_text.insert(tk.END, "\nLog Files\n")
        self.status_text.insert(tk.END, "=========\n\n")

        for name, path in self.log_files.items():
            self.status_text.insert(tk.END, name + ": " + path + "\n")

    def auto_refresh_status(self):
        self.refresh_status()
        self.root.after(1000, self.auto_refresh_status)

    def refresh_logs(self):
        selected = self.selected_log.get()
        path = self.log_files.get(selected)

        if selected == "Suspicious Alerts DB":
            rows = read_alerts(path)

            text = "Suspicious Alerts DB\n"
            text += "====================\n\n"
            text += "Rows loaded: " + str(len(rows)) + "\n\n"

            for row in rows[:100]:
                text += " | ".join(str(value) for value in row) + "\n"

        else:
            text = read_file_tail(path)

        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, text)

    def clear_selected_log(self):
        selected = self.selected_log.get()
        path = self.log_files.get(selected)

        if not path:
            return

        confirm = messagebox.askyesno(
            "Clear Log",
            "Clear this log?\n\n" + selected + "\n" + path
        )

        if not confirm:
            return

        try:
            if selected == "Suspicious Alerts DB":
                connection = sqlite3.connect(path)
                cursor = connection.cursor()
                cursor.execute("DELETE FROM alerts")

                try:
                    cursor.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
                except sqlite3.Error:
                    pass

                connection.commit()
                connection.close()

            else:
                with open(path, "w", encoding="utf-8") as file:
                    file.write("")

            self.refresh_logs()
            self.refresh_alerts()

        except Exception as error:
            messagebox.showerror("Clear Error", str(error))

    def refresh_alerts(self):
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)

        rows = read_alerts(self.alerts_db)

        for row in rows:
            self.alert_tree.insert("", "end", values=row)

        self.alert_count_label.configure(text="Rows: " + str(len(rows)))

    def refresh_everything(self):
        self.refresh_status()
        self.refresh_logs()
        self.refresh_alerts()

    def open_folder(self):
        try:
            if os.name == "nt":
                os.startfile(BASE_DIR)
            else:
                messagebox.showinfo("Folder Location", BASE_DIR)

        except Exception as error:
            messagebox.showerror("Open Folder Error", str(error))

    def on_close(self):
        self.stop_all()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = HIDS_UI(root)
    root.mainloop()
