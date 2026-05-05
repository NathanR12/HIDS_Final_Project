import os
import hashlib
import Config

CONFIG = Config.Load_Config()

Hash_Storage = CONFIG["logs"]["hash_storage"]


def Get_File_Hash(src_path):                         ##function to grab a specific hash when function called, path taken from watchdog.
    try:                                                #may fail so try is used.
        sha256_hash = hashlib.sha256()                                                          #
        with open(src_path, "rb") as file:                                  #opens the file and reads contents
            for byte_block in iter(lambda: file.read(4096), b""):                   
                sha256_hash.update(byte_block)                              #reads the file chunk by chunk (4096 bytes) then feeds into sha-256 piece by piece
        return sha256_hash.hexdigest()                                    #returns once completed
    except FileNotFoundError:
        return None                                                             #except when no file or no permissions are there
    except PermissionError:
        return None
def Load_Hashes():
    hashes = {}                                                                                 #creating a dictionairy for easier use and active storage.
    if not os.path.exists(Hash_Storage):                               ###if there are no hashes to check yet value is returned.
        return hashes

    with open(Hash_Storage, "r", encoding="utf-8") as file:                                #######tells to read storage, encoding=utf8 is to read safelely???
        for line in file:                                                                       ####goes through each line
            line = line.strip()                                                             ###removes extra spaces

            if " | " in line:                                                   #line debugs an errors caused by wrongly saved path and hash, if broken it will return original hash value.
                file_path, file_hash = line.split(" | ", 1)                                 ### split once, path and hash
                hashes[file_path] = file_hash                                               #saves hash and hash

    return hashes                                                                          # returns saved to dictionairy

def Save_Hashes(hashes):
    with open(Hash_Storage, "w", encoding="utf-8") as file:
        for file_path in hashes:
            file.write(file_path + " | " + hashes[file_path] + "\n")                # adding a new entry \n sets new line

def Check_File_Hash(src_path):                                                      #main function for watchdog, checks suspicous for new, unchanged, changed, cant be checked
    results = []                                                                #creates empty list to return to watchdog for loggin

    current_hash = Get_File_Hash(src_path)                                          #gets the hash of the file right now

    if current_hash is None:
        results.append("Could not hash file: " + src_path)                             #if there is not hahs for the suspicious file this message is returened to results
        return results

    hashes = Load_Hashes()                                              #gets the old hash for the path                                 

    if src_path not in hashes:                                      #checks to see if path is new
        hashes[src_path] = current_hash                                #saves the hash for the new file
        Save_Hashes(hashes)                                             #updates dictionairy

        results.append("New suspicious file hash saved")            
        results.append("SHA256: " + current_hash)               #reports and returns to watchdog logs the new information
        return results

    old_hash = hashes[src_path]                                     

    if old_hash != current_hash:                                        #compares the old hash it has just grabbed to the new hash created in the function above
        results.append("HASH CHANGE DETECTED")                  # if not the same hash has been changed displaying message with all information
        results.append("Old hash: " + old_hash)
        results.append("New hash: " + current_hash)

        hashes[src_path] = current_hash                                     #updates hash to the new one finishing the check   
        Save_Hashes(hashes)                                                 #sends the update to the function to process into file
    else:

        results.append("Hash verified, no change detected")             #if none are true then this is printed with confirmation.
        results.append("SHA256: " + current_hash)

    return results   