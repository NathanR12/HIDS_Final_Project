import os  
import yara  


RULE_FILE = "HIDS_Rules.yar"  


def Check_File_Yara(src_path):
    results = []

    if not os.path.exists(src_path):
        results.append("YARA: File no longer exists, cannot scan: " + src_path)
        return results

    if os.path.isdir(src_path):
        results.append("YARA: Path is a directory, skipping scan: " + src_path)
        return results

    if not os.path.exists(RULE_FILE):
        results.append("YARA: Rule file not found: " + RULE_FILE)
        return results

    try:
        rules = yara.compile(filepath=RULE_FILE)  
        matches = rules.match(src_path)           

        if matches:
            results.append("========== YARA MATCH DETECTED ==========")
            results.append("File: " + src_path)

            for match in matches:
                results.append("YARA Rule Matched: " + str(match.rule))

            results.append("=========================================")

        else:
            results.append("YARA Scan: No matches found for: " + src_path)

    except yara.Error as error:
        results.append("YARA Error while scanning " + src_path + ": " + str(error))

    except PermissionError:
        results.append("YARA: No permission to scan: " + src_path)

    except Exception as error:
        results.append("YARA Unknown Error while scanning " + src_path + ": " + str(error))

    return results