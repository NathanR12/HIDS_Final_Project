import time # allows creation of loops and timestamps
import psutil # is used to monitor processes such as usage and file logging.
import YaraV
import SQLite3LOG
import Config

CONFIG = Config.Load_Config()

class ProcessCheck:                             ##creating class
    Log_File = CONFIG["logs"]["process_log"]

    CHECK_INTERVAL = CONFIG["process"]["check_interval_seconds"]

    CPU_Percent_Limit = CONFIG["process"]["cpu_percent_limit"]
    Memory_Percent_Limit = CONFIG["process"]["memory_percent_limit"]

    Suspicious_Process_Names = {
        name.lower()
        for name in CONFIG["process"]["suspicious_process_names"]
    }

    Suspicious_Paths = {
        path.lower()
        for path in CONFIG["process"]["suspicious_paths"]
    }

    def __init__(self):
            self.seen_processes = set()                     #stores process ids that have been seen
            self.logged_findings = {}                       #stores already logged alerts
            self.Recheck_Time = CONFIG["process"]["recheck_time_seconds"]
            

    def Log_To_File(self, message):                                     ## writes a messgae to the log file
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")                          #timestamp for logged events

        with open(self.Log_File, "a", encoding="utf-8") as file:            #opens log in "a" append mode, allowing alerts to be adding at the bottom
            file.write("[" + timestamp + "] " + message + "\n")             # writes the timestamp and message

    def Log_Suspicious_Process(self, pid, name, exe_path, reasons):                     ## logs suspicious alerts withsaid taken inputs.
        self.Log_To_File("========== SUSPICIOUS PROCESS DETECTED ==========")    ##alert message 
        self.Log_To_File("PID: " + str(pid))                                      ##pid record
        self.Log_To_File("Process Name: " + str(name))                          ##process name record
        self.Log_To_File("Executable Path: " + str(exe_path))                   ##path record

        for reason in reasons:                                          ##looped to seperate the possibility of multipul reasons
            self.Log_To_File("Reason: " + reason)                       ##list of flagged reasons

        SQLite3LOG.Log_Alert(
            alert_type="Suspicious Process",
            source="ProcessCheck",
            pid=pid,
            process_name=name,
            exe_path=exe_path,
            reasons=reasons
        )

        if exe_path is not None:
            yara_results = YaraV.Check_File_Yara(exe_path)              ###########################################################CAN ONLY RUN WHEN CONDITIONS OF SUSPICOUS IS MET
                                                                                #####################################################################################
            for result in yara_results:
                self.Log_To_File(result)

        self.Log_To_File("=================================================")   ##ending alert

    def Check_Process(self, process):                                 ##checks one running process against the rules
        try:
            pid = process.pid                                   #process ID
            name = process.name()                               #process name
            exe_path = process.exe()                            ##full path
            reasons = []                                        ##empty list, holds later reasons for suspicion.
            ##always checks our suspicious rules and paths
            if name.lower() in self.Suspicious_Process_Names:                       ##if (lowercase) name of process matches process in suspicious process names its reported
                reasons.append("Suspicious process name detected: " + name)         ## if names match, reasons is updated
            if exe_path is not None:                                                   #checks the path exsists                                     
                exe_path_lower = exe_path.lower()                                       ##converts to lowercase

                for suspicious_path in self.Suspicious_Paths:                               #if suspicious path is matched to rules
                    if suspicious_path in exe_path_lower:
                        reasons.append("Process running from suspicious path: " + suspicious_path)   ## adds reason and appends list.
            if reasons:                                                                                 #if reasons has data
                finding_key = (pid, tuple(sorted(reasons)))                                             #create unique key, uses pid and reasons, uses tuple as this cannot be changed, sorted ensures the list is always consistant. Ensures the same reasons create the same key everytime
                current_time = time.time()
                last_logged_time = self.logged_findings.get(finding_key)                                    ## checks when this same alert was last logged

                if last_logged_time is None or current_time - last_logged_time >= self.Recheck_Time:        ## if not logged before, log now. Otherwise log if 5 mins have passed.
                    self.logged_findings[finding_key] = current_time                                        #
                    self.Log_Suspicious_Process(pid, name, exe_path, reasons)                               #appends fields to be returned.
        
        except psutil.NoSuchProcess:            ## debugs any disappearing processes
            return

        except psutil.AccessDenied:                                                                                 ##debugs if acess is denied by windows when in check
            self.Log_To_File("Access denied while checking process PID: " + str(process.pid))    #gives message with id

        except psutil.ZombieProcess:                        ## debugs any dead processes(a process that looks active but is not)        
            return
            
    def Check_System_Usage(self):                                   ##checks CPU and Memory Usage
            cpu_percent = psutil.cpu_percent(interval=1)            ## gets cpu usage across the whole computer, interval 1 means it takes 1 second to mesure CPU usage
            memory_percent = psutil.virtual_memory().percent        ## gets total system memory as percentage

            reasons = []                                            ##empty list for alerts

            if cpu_percent >= self.CPU_Percent_Limit:                                                           #checks wether cpu usage is aboce 80%
                reasons.append("High total CPU usage detected: " + str(round(cpu_percent, 2)) + "%")            #if so reasons append
            
            if memory_percent >= self.Memory_Percent_Limit:                                                     #checks wether Memory usage is above 80%
                reasons.append("High total memory usage detected: " + str(round(memory_percent, 2)) + "%")      #if so reasons append, rounds memory percent to 2dp and turns into text for ease of logging and compatibility
            
            if reasons:
                finding_key = ("SYSTEM USAGE", tuple(sorted(reasons)))              ##does not use PID so a key is created.
                current_time = time.time()                                          ##gets the current time
                last_logged_time = self.logged_findings.get(finding_key)            ##checks when the same system alert was last logged
                                                                                                                               
                if last_logged_time is None or current_time - last_logged_time >= self.Recheck_Time:            ##if never logged before, alert is logged, otherwise 5 minutes is needed since the same last alert was made.
                    self.logged_findings[finding_key] = current_time                                        #if previous conditions met, stores/updates the time this alert was last logged 
                    self.Log_To_File("========== SUSPICIOUS SYSTEM EVENT DETECTED ==========")              #adds border to this alert

                    for reason in reasons:                                                              ##uses reasons to display in logs, seperated by clear identifiers
                        self.Log_To_File("Reason: " + reason)

                    PandasLog.Log_Alert(
                        alert_type="Suspicious System Usage",
                        source="ProcessCheck",
                        reasons=reasons
                    ) 

                    self.Log_To_File("======================================================")
            

    def Start_Monitoring(self):                                         #loops the entire system, saves id, logs monitoring started
        self.Log_To_File("Process monitoring started")                          ## alert that monitoring has started, sent to log to file so it will come with timestamp. 
        
        for process in psutil.process_iter(["pid"]):                ##loops through all running processes, only asks for PID      
            try:
                self.seen_processes.add(process.info["pid"])        ##Adds each pid to the seen_processes set
            except psutil.NoSuchProcess:                            ##except if no processes are available
                continue

        try:
            while True:                                             #runs monitor forever, only false if user cancels it
                self.Check_System_Usage()                           #runs check system storage process
                for process in psutil.process_iter(["pid"]):        # loops every running process, psutil.process_iter() feeds one process object at a time
                    pid = process.info["pid"]               

                    if pid not in self.seen_processes:              #checks if pid has been seen before, if not in seen_processes it adds it
                        self.seen_processes.add(pid)

                    self.Check_Process(process)             #uses process to check suspicous names or paths

                time.sleep(self.CHECK_INTERVAL)             #pauses before next scan, saving recourses.

        except KeyboardInterrupt:                               #except upon user interaction
            self.Log_To_File("Process monitoring stopped")


if __name__ == "__main__":              #main program startup
    monitor = ProcessCheck()            #creates new object, auto starts __init__
    monitor.Start_Monitoring()          ## starts the loop 
