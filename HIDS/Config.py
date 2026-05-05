import os
import json

CONFIG_FILE = "HIDS_Rules_Config.json"


def Load_Config():
    with open(CONFIG_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def Expand_Path(path):
    return os.path.expandvars(path)


def Get_Watchdog_Paths(config):
    paths = []

    for path in config["watchdog"]["important_paths"]:
        paths.append(Expand_Path(path))
  
    return paths

def Get_Ignored_Paths(config):
    paths = []

    for path in config["watchdog"].get("ignored_paths", []):
        paths.append(Expand_Path(path).lower())

    return paths
