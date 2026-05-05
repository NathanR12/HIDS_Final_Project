import os
import time
import json
import win32evtlog
import win32con
import Config
import SQLite3LOG

CONFIG = Config.Load_Config()


class WinEventCheck:
    LOG_FILE = CONFIG["logs"]["windows_event_log"]
    STATE_FILE = CONFIG["logs"]["windows_event_state"]

    CHECK_INTERVAL = CONFIG["windows_events"]["check_interval_seconds"]

    Logs_To_Check = {
        log_name: {
            int(event_id): reason
            for event_id, reason in event_rules.items()
        }
        for log_name, event_rules in CONFIG["windows_events"]["logs_to_check"].items()
    }

    Event_Types = {
        win32con.EVENTLOG_ERROR_TYPE: "Error",
        win32con.EVENTLOG_WARNING_TYPE: "Warning",
        win32con.EVENTLOG_INFORMATION_TYPE: "Information",
        win32con.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
        win32con.EVENTLOG_AUDIT_FAILURE: "Audit Failure"
    }

    def __init__(self):
        self.last_records = self.Load_State()

    def Log_To_File(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        with open(self.LOG_FILE, "a", encoding="utf-8") as file:
            file.write("[" + timestamp + "] " + message + "\n")

    def Load_State(self):
        if not os.path.exists(self.STATE_FILE):
            return {}

        try:
            with open(self.STATE_FILE, "r", encoding="utf-8") as file:
                return json.load(file)
        except:
            return {}

    def Save_State(self):
        with open(self.STATE_FILE, "w", encoding="utf-8") as file:
            json.dump(self.last_records, file, indent=4)

    def Get_Event_Type(self, event_type):
        return self.Event_Types.get(event_type, "Unknown")

    def Get_Event_Message(self, event):
        if event.StringInserts:
            return " | ".join(str(item) for item in event.StringInserts)
        return "No message data available"

    def Get_Current_Last_Record(self, log_name):
        try:
            handle = win32evtlog.OpenEventLog(None, log_name)
            total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
            oldest_record = win32evtlog.GetOldestEventLogRecord(handle)
            win32evtlog.CloseEventLog(handle)

            if total_records == 0:
                return 0

            return oldest_record + total_records - 1

        except Exception as error:
            self.Log_To_File("Could not read current record for " + log_name + ": " + str(error))
            return 0

    def Setup_First_Run(self):
        for log_name in self.Logs_To_Check:
            if log_name not in self.last_records:
                self.last_records[log_name] = self.Get_Current_Last_Record(log_name)

        self.Save_State()

    def Check_Log(self, log_name):
        suspicious_ids = self.Logs_To_Check[log_name]

        try:
            handle = win32evtlog.OpenEventLog(None, log_name)

            last_record = self.last_records.get(log_name, 0)
            highest_record = last_record

            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            new_events = []
            events = win32evtlog.ReadEventLog(handle, flags, 0)

            while events:
                stop_reading = False

                for event in events:
                    record_number = event.RecordNumber

                    if record_number <= last_record:
                        stop_reading = True
                        break

                    new_events.append(event)

                    if record_number > highest_record:
                        highest_record = record_number

                if stop_reading:
                    break

                events = win32evtlog.ReadEventLog(handle, flags, 0)

            for event in reversed(new_events):
                event_id = event.EventID & 0xFFFF

                if event_id in suspicious_ids:
                    self.Log_Suspicious_Event(log_name, event, suspicious_ids[event_id])

            self.last_records[log_name] = highest_record
            self.Save_State()

            win32evtlog.CloseEventLog(handle)

        except Exception as error:
            self.Log_To_File("Could not check " + log_name + " log: " + str(error))

    def Log_Suspicious_Event(self, log_name, event, reason):
        event_id = event.EventID & 0xFFFF
        event_type = self.Get_Event_Type(event.EventType)
        message = self.Get_Event_Message(event)

        self.Log_To_File("========== WINDOWS EVENT DETECTED ==========")
        self.Log_To_File("Log Name: " + log_name)
        self.Log_To_File("Event ID: " + str(event_id))
        self.Log_To_File("Reason: " + reason)
        self.Log_To_File("Event Type: " + event_type)
        self.Log_To_File("Source: " + str(event.SourceName))
        self.Log_To_File("Record Number: " + str(event.RecordNumber))
        self.Log_To_File("Time Generated: " + str(event.TimeGenerated))
        self.Log_To_File("Message Data: " + message)
        self.Log_To_File("============================================")

        try:
            SQLite3LOG.Log_Alert(
                alert_type="Windows Event",
                source="WinEventCheck",
                event=log_name + " Event ID " + str(event_id),
                reasons=[
                    reason,
                    "Event Type: " + event_type,
                    "Source: " + str(event.SourceName),
                    "Record Number: " + str(event.RecordNumber),
                    "Time Generated: " + str(event.TimeGenerated),
                    "Message Data: " + message
                ]
            )
        except Exception as error:
            self.Log_To_File("Pandas CSV logging failed: " + str(error))

            
    def Start_Monitoring(self):
        self.Log_To_File("Windows Event Log monitoring started")

        self.Setup_First_Run()

        try:
            while True:
                for log_name in self.Logs_To_Check:
                    self.Check_Log(log_name)

                time.sleep(self.CHECK_INTERVAL)

        except KeyboardInterrupt:
            self.Log_To_File("Windows Event Log monitoring stopped")


if __name__ == "__main__":
    monitor = WinEventCheck()
    monitor.Start_Monitoring()
