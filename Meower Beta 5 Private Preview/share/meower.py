from cloudlink import CloudLink
from better_profanity import profanity
import sys
import os
import string
import random
import bcrypt
import json
from datetime import datetime
import time
import traceback

"""

Meower Social Media Platform - Server Source Code

Dependencies:
* CloudLink >=0.1.7.4
* better-profanity
* bcrypt
* traceback
* datetime
* os
* sys
* random

"""

def full_stack():
    import traceback, sys
    exc = sys.exc_info()[0]
    if exc is not None:
        f = sys.exc_info()[-1].tb_frame.f_back
        stack = traceback.extract_stack(f)
    else:
        stack = traceback.extract_stack()[:-1]  # last one would be full_stack()
    trc = 'Traceback (most recent call last):\n'
    stackstr = trc + ''.join(traceback.format_list(stack))
    if exc is not None:
        stackstr += '  ' + traceback.format_exc().lstrip(trc)
    return stackstr

class files: # Storage API for... well... storing things.
    def __init__(self):
        self.dirpath = os.path.dirname(os.path.abspath(__file__)) + "/Meower"
        print("Files class ready.")
    
    def init_files(self):
        for directory in [
            "./Meower/",
            "./Meower/Storage",
            "./Meower/Storage/Posts",
            "./Meower/Storage/Categories",
            "./Meower/Storage/Categories/Home",
            "./Meower/Storage/Categories/Announcements",
            "./Meower/Storage/Categories/Chats",
            "./Meower/Userdata",
            "./Meower/Logs",
            "./Meower/Config",
            "./Meower/Jail",
        ]:
            try:
                os.mkdir(directory)
            except FileExistsError:
                pass
         
        # Create server account file
        data = json.dumps({"user_settings": {}, "user_data": {"pfp_data": "22", "quote": ""}, "secure_data": {"email": "", "pswd": "", "lvl": "0", "banned": False}})
        self.write("/Userdata/", "Server.json", data)
        
        # Create deleted account file
        data = json.dumps({"user_settings": {}, "user_data": {"pfp_data": "22", "quote": ""}, "secure_data": {"email": "", "pswd": "", "lvl": "0", "banned": False}})
        self.write("/Userdata/", "Deleted.json", data)
        
        # Create IP banlist file
        result, filecheck = self.lsdir("/Jail")
        if result:
            if not "IPBanlist.json" in filecheck:
                data = json.dumps({
                    "wildcard": [
                        "127.0.0.1",
                    ],
                    "users": {
                        "Deleted": "127.0.0.1",
                        "Server": "127.0.0.1",
                    }
                })
                
                self.write("/Jail/", "IPBanlist.json", data)
        
        # Create Version support file
        result, filecheck = self.lsdir("/Config")
        if result:
            if not "supported_versions.json" in filecheck:
                data = json.dumps({"index": ["scratch-beta-5-r1"]})
                self.write("/Config/", "supported_versions.json", data)
        
        # Create Trust Keys file
        result, filecheck = self.lsdir("/Config")
        if result:
            if not "trust_keys.json" in filecheck:
                data = json.dumps({"index": ["meower"]})
                self.write("/Config/", "trust_keys.json", data)
    
    def write(self, fdir, fname, data):
        try:
            if os.path.exists(self.dirpath + "/" + fdir):
                if type(data) == str:
                    f = open((self.dirpath + "/" + fdir + "/" + fname), "w")
                    f.write(data)
                    f.close()
                elif type(data) == dict:
                    f = open((self.dirpath + "/" + fdir + "/" + fname), "w")
                    f.write(json.dumps(data))
                    f.close()
                else:
                    f = open((self.dirpath + "/" + fdir + "/" + fname), "w")
                    f.write(str(data))
                    f.close()
                return True
            else:
                return False
        except Exception as e:
            print(full_stack())
            return False
    
    def mkdir(self, directory):
        check1 = False
        try:
            os.makedirs((self.dirpath + "/" + directory), exist_ok=True)
            check1 = True
            return True
        except Exception as e:
            print(full_stack())
            return False
    
    def rm(self, file):
        try:
            os.remove((self.dirpath + "/" + file))
            return True
        except Exception as e:
            print(full_stack())
            return False
    
    def rmdir(self, directory):
        try:
            check1 = os.rmdir((self.dirpath + "/" + directory))
            if check1:
                return True
            else:
                return False, 2
        except Exception as e:
            print(full_stack())
            return False, 1
    
    def read(self, fname):
        try:
            if os.path.exists(self.dirpath + "/" + fname):
                dataout = open(self.dirpath + "/" + fname).read()
                return True, dataout
            else:
                return False, None
        except Exception as e:
            print(full_stack())
            return False, None
    
    def chkfile(self, file):
        try:
            return True, os.path.exists(self.dirpath + "/" + file)
        except Exception as e:
            return False, None
    
    def lsdir(self, directory):
        try:
            return True, os.listdir(self.dirpath + "/" +directory)
        except Exception as e:
            print(full_stack())
            return False, None
    
    def chktype(self, directory, file):
        try:
            if os.path.isfile(self.dirpath + "/" + directory + "/" + file):
                return True, 1
            elif os.path.isdir(self.dirpath + "/" + directory + "/" + file):
                return True,  2
            else:
                return False, None
        except Exception as e:
            print(full_stack())
            return False, None

class security: # Security API for generating/checking passwords, creating session tokens and authentication codes
    def __init__(self):
        self.bc = bcrypt
        self.fs = files()
        print("Security class ready.")
    
    def create_pswd(self, password, strength=12): # bcrypt hashes w/ salt
        if type(password) == str:
            if type(strength) == int:
                pswd_bytes = bytes(password, "utf-8")
                hashed_pw = self.bc.hashpw(pswd_bytes, self.bc.gensalt(strength))
                return hashed_pw.decode()
            else:
                error = "Strength parameter is not " + str(int) + ", got " + str(type(strength))
                raise TypeError(error)
        else:
            error = "Password parameter is not " + str(str) + ", got " + str(type(password))
            raise TypeError(error)
    
    def check_pswd(self, password, hashed_pw): # bcrypt checks
        if type(password) == str:
            if type(hashed_pw) == str:
                pswd_bytes = bytes(password, "utf-8")
                hashed_pw_bytes = bytes(hashed_pw, "utf-8")
                return self.bc.checkpw(pswd_bytes, hashed_pw_bytes)
            else:
                error = "Hashed password parameter is not " + str(str) + ", got " + str(type(hashed_pw))
                raise TypeError(error)
        else:
            error = "Password parameter is not " + str(str) + ", got " + str(type(password))
            raise TypeError(error)

    def gen_token(self): # Generates a unique session token.
        output = ""
        for i in range(50):
            output += random.choice('0123456789ABCDEFabcdef')
        return output

    def gen_key(self): # Generates a 6-digit key for Meower Authenticator.
        output = ""
        for i in range(6):
            output += random.choice('0123456789')
        return output

    def read_user_account(self, username): # Reads the contents of the username's account. Returns true if the account exists and has been read back correctly.
        if type(username) == str:
            result, dirlist = self.fs.lsdir("/Userdata/")
            if result:
                if str(username + ".json") in dirlist: # Read back the userfile
                    result2, payload = self.fs.read("/Userdata/" + str(username + ".json"))
                    if result2:
                        try:
                            return True, json.loads(payload)
                        except json.decoder.JSONDecodeError:
                            print(('Error while decoding user "{0}"'+"'s json data").format(username))
                            return False, None
                    else:
                        return False, None
                else:
                    return False, True
            else:
                return False, None
        else:
            return False, None
    
    def write_user_account(self, username, new_data): # Returns true if the account does not exist and has been generated successfully.
        if type(username) == str:
            result, dirlist = self.fs.lsdir("/Userdata/")
            if result:
                if str(username + ".json") in dirlist:
                    if type(new_data) == dict:
                        result2 = self.fs.write("/Userdata/", str(username + ".json"), json.dumps(new_data))
                        if result2:
                            pass
                        else:
                            print("Account modify err")
                        return True, result2 # Both true - Account modified OK, if result is false - Server error
                    else:
                        print("Account modifier datatype error")
                        return False, False # The datatype is not valid
                else:
                    print("Account does not exist")
                    return False, True # Account does not exist
            else:
                print("Account server error")
                return False, False # Server error
        else:
            print("Account server error")
            return False, False # Server error
    
    def gen_user_account(self, username): # Returns true if the account does not exist and has been generated successfully.
        if type(username) == str:
            result, dirlist = self.fs.lsdir("/Userdata/")
            if result:
                if not str(username + ".json") in dirlist:
                    tmp = {
                        "user_settings": {
                            "theme": "orange",
                            "mode": True,
                            "sfx": True,
                            "debug": False,
                            "bgm": True,
                            "bgm_song": "Voxalice - Percussion bass loop",
                            "layout": "new"
                        },
                        "user_data": {
                            "pfp_data": "1",
                            "quote": "" # User's quote
                        },
                        "secure_data": {
                            "email": "", # TODO: Add an Email bot for account recovery
                            "pswd": "", # STORE ONLY SALTED HASHES FOR PASSWORD, DO NOT STORE PLAINTEXT OR UNSALTED HASHES
                            "lvl": "0", # Account levels. 
                            "banned": False # Banned?
                        }
                    }
                    result2 = self.fs.write("/Userdata/", str(username + ".json"), json.dumps(tmp))
                    if result2:
                        pass
                    else:
                        print("Account gen err")
                    return True, result2 # Both true - Account generated OK, if result is false - Server error
                else:
                    return False, True # Account exists
            else:
                print("Account server error")
                return False, False # Server error
        else:
            print("Account server error")
            return False, False # Server error

class meower(files, security): # Meower Server itself, TODO: Optimize and refactor code since some parts aren't consistent
    def __init__(self, debug=False, ignoreUnauthedBlanks=False):
        self.cl = CloudLink(debug=debug)
        self.ignoreUnauthedBlanks = ignoreUnauthedBlanks
        
        # Add custom status codes to CloudLink
        self.cl.codes["KeyNotFound"] = "I:010 | Key Not Found"
        self.cl.codes["PasswordInvalid"] = "I:011 | Invalid Password"
        self.cl.codes["GettingReady"] = "I:012 | Getting ready"
        self.cl.codes["ObsoleteClient"] = "I:013 | Client is out-of-date or unsupported"
        self.cl.codes["Pong"] = "I:014 | Pong"
        self.cl.codes["IDExists"] = "I:015 | Account exists"
        self.cl.codes["2FAOnly"] = "I:016 | 2FA Required"
        self.cl.codes["MissingPermissions"] = "I:017 | Missing permissions"
        self.cl.codes["Banned"] = "E:018 | Account Banned"
        self.cl.codes["IllegalChars"] = "E:019 | Illegal characters detected"
        self.cl.codes["Kicked"] = "E:020 | Kicked"
        
        clear_cmd = "cls" # Change for os-specific console clear
        # Instanciate the other classes into Meower
        self.fs = files()
        self.secure = security()
        
        # init the filesystem
        self.fs.init_files()
        
        # Create permitted lists of characters
        self.permitted_chars_username = []
        self.permitted_chars_post = []
        for char in string.ascii_letters:
            self.permitted_chars_username.append(char)
            self.permitted_chars_post.append(char)
        for char in string.digits:
            self.permitted_chars_username.append(char)
            self.permitted_chars_post.append(char)
        for char in string.punctuation:
            self.permitted_chars_username.append(char)
            self.permitted_chars_post.append(char)
        for char in '{}[]"-()':
            self.permitted_chars_username.remove(char)
        for char in '{}[]"()':
            self.permitted_chars_post.remove(char)
        self.permitted_chars_username.append(" ")
        self.permitted_chars_post.append(" ")
        
        # Peak number of users logger
        self.peak_users_logger = {
            "count": 0,
            "timestamp": {
                "mo": 0,
                "d": 0,
                "y": 0,
                "h": 0,
                "mi": 0,
                "s": 0
            }
        }
        
        # Create callbacks
        self.cl.callback("on_packet", self.on_packet)
        self.cl.callback("on_close", self.on_close)
        self.cl.callback("on_connect", self.on_connect)
        
        # Create chat handler
        self.chats = {}
        
        """
        
        Example reference for chats (excluding livechat, as that chat is purely stateless)
        
        self.chats = {
            "test": {
                "owner": "MikeDEV",
                "userlist": [
                    "MikeDEV"
                ],
                "memref": [(Memory objects)]
            }
        }
        
        """
        
        # Load the supported versions list
        result, payload = self.fs.read("/Config/supported_versions.json")
        if result:
            payload = json.loads(payload)
            self.versions_supported = payload["index"]
            result, payload = self.fs.read("/Config/trust_keys.json")
            if result:
                payload = json.loads(payload)
                self.cl.trustedAccess(True, payload["index"])
                # Load the IP blocklist file
                result, payload = self.fs.read("/Jail/IPBanlist.json")
                if result:
                    payload = json.loads(payload)
                    self.cl.loadIPBlocklist(payload["wildcard"])
                    self.cl.setMOTD("Meower Social Media Platform Server", enable=True)
                    os.system(clear_cmd+" && echo Meower Social Media Platform Server")
                    self.cl.server(port=3000)
                else:
                    os.system(clear_cmd)
                    print("Failed to load IP blocklist!")
                    exit
            else:
                os.system(clear_cmd)
                print("Failed to load trust keys!")
                exit 
        else:
            os.system(clear_cmd)
            print("Failed to load version support list!")
            exit
    
    def log(self, event):
        today = datetime.now()
        now = today.strftime("%m/%d/%Y %H:%M.%S")
        print("{0}: {1}".format(now, event))

    def get_client_statedata(self, client): # "steals" information from the CloudLink module to get better client data
        if type(client) == str:
            client = self.cl._get_obj_of_username(client)
        if not client == None:
            if client['id'] in self.cl.statedata["ulist"]["objs"]:
                tmp = self.cl.statedata["ulist"]["objs"][client['id']]
                return tmp
            else:
                return None
    
    def modify_client_statedata(self, client, key, newvalue): # WARN: Use with caution: DO NOT DELETE UNNECESSARY KEYS!
        if type(client) == str:
            client = self.cl._get_obj_of_username(client)
        if not client == None:
            if client['id'] in self.cl.statedata["ulist"]["objs"]:
                try:
                    self.cl.statedata["ulist"]["objs"][client['id']][key] = newvalue
                    return True
                except Exception as e:
                    print(full_stack())
                    return False
            else:
                return False
    
    def delete_client_statedata(self, client, key): # WARN: Use with caution: DO NOT DELETE UNNECESSARY KEYS!
        if type(client) == str:
            client = self.cl._get_obj_of_username(client)
        if not client == None:
            if client['id'] in self.cl.statedata["ulist"]["objs"]:
                if key in self.cl.statedata["ulist"]["objs"][client['id']]:
                    try:
                        del self.cl.statedata["ulist"]["objs"][client['id']][key]
                        return True
                    except Exception as e:
                        print(full_stack())
                        return False
            else:
                return False
    
    def update_indexer(self, new_data, location="/Categories/Home/"):
        status, payload = self.get_indexer(location=location, truncate=False, convert=False)
        today = datetime.now()
        today = str(today.strftime("%d%m%Y"))
        if status != 0:
            payload.append(new_data)
            result = self.fs.write(("/Storage" + str(location)), today, {"index": payload})
            return result
        else:
            return False
    
    def get_indexer(self, location="/Categories/Home/", truncate=False, convert=False, mode="Latest", searchLvl=0):
        today = datetime.now()
        today = str(today.strftime("%d%m%Y"))
        result, dirlist = self.fs.lsdir("/Storage/Categories/Home/")
        if result:
            if today in dirlist:
                result2, payload = self.fs.read(str("/Storage" + str(location) + today))
                try:
                    payload = json.loads(payload)
                    payload = payload["index"]
                except Exception as e:
                    self.log("Error on get_home function: {0}".format(full_stack()))
                    return 0, None, None
                
                if result2:
                    if truncate:
                        # Truncate home to 25 items.
                        if len(payload) > 25:
                            if mode == "Latest":
                                payload = payload[(len(payload)-25):len(payload)]
                            elif mode == "Search":
                                #TODO: Add searching features
                                pass
                    
                    if convert:
                        #convert list to format that meower can use
                        tmp1 = ""
                        for item in payload:
                            tmp1 = str(tmp1 + item + ";")
                        return 2, tmp1
                    else:
                        return 2, payload
                else:
                    return 0, None
            else:
                result2 = self.fs.write(("/Storage" + str(location)), today, {"index":[]})
                if result2:
                    return 1, ";"
                else:
                    return 0, None
        else:
            return 0, None, None
    
    def create_system_message(self, post):
        today = datetime.now()
        # Generate a post ID
        post_id = str(today.strftime("%d%m%Y%H%M%S")) 
        post_id = "Server-" + post_id
        
        # Attach metadata to post
        post_w_metadata = {
            "t": {
                "mo": (datetime.now()).strftime("%m"),
                "d": (datetime.now()).strftime("%d"),
                "y": (datetime.now()).strftime("%Y"),
                "h": (datetime.now()).strftime("%H"),
                "mi": (datetime.now()).strftime("%M"),
                "s": (datetime.now()).strftime("%S"),
            },
            "p": post,
            "post_origin": "home"
        }
        post_w_metadata["u"] = "Server"
        
        # Read back current homepage state (and create a new homepage if needed)
        status, payload = self.get_indexer(location="/Categories/Home/")
        
        # Check status of homepage
        if status != 0:
            # Update the current homepage
            result = self.update_indexer(post_id, location="/Categories/Home/")
            if result:
                # Store the post
                result2 = self.fs.write("/Storage/Posts", post_id, post_w_metadata)
                
                self.log("Created system message with ID {0}".format(post_id))
                
                relay_post = post_w_metadata
                relay_post["mode"] = 1
                relay_post["post_id"] = str(post_id)
                self.log("Relaying system message {0}".format(post_id))
                self.sendPacket({"cmd": "direct", "val": relay_post})
                return result2
            else:
                return False
        else:
            return False
    
    def on_close(self, client):
        if type(client) == dict:
            self.log("{0} Disconnected.".format(client["id"]))
        elif type(client) == str:
            self.log("{0} Logged out.".format(self.cl._get_username_of_obj(client)))
        self.log_peak_users()
    
    def on_connect(self, client):
        self.log("{0} Connected.".format(client["id"]))
        self.modify_client_statedata(client, "authtype", "")
        self.modify_client_statedata(client, "authed", False)
        
        # Rate limiter
        today = datetime.now()
        self.modify_client_statedata(client, "last_packet", {
            "h": today.strftime("%H"),
            "m": today.strftime("%M"),
            "s": today.strftime("%S")
        })
    
    def log_peak_users(self):
        current_users = len(self.cl.getUsernames())
        if current_users > self.peak_users_logger["count"]:
            today = datetime.now()
            self.peak_users_logger = {
                "count": current_users,
                "timestamp": {
                    "mo": (datetime.now()).strftime("%m"),
                    "d": (datetime.now()).strftime("%d"),
                    "y": (datetime.now()).strftime("%Y"),
                    "h": (datetime.now()).strftime("%H"),
                    "mi": (datetime.now()).strftime("%M"),
                    "s": (datetime.now()).strftime("%S")
                }
            }
            self.log("New peak in # of concurrent users: {0}".format(current_users))
            self.create_system_message("Yay! New peak in # of concurrent users: {0}".format(current_users))
            payload = {
                "mode": "peak",
                "payload": self.peak_users_logger
            }
            self.sendPacket({"cmd": "direct", "val": payload})
    
    def check_for_spam(self, client):
        today = datetime.now()
        current_time = int(today.strftime("%H%M%S"))
        self.log("Current time is {0}".format(current_time))
        not_formatter = self.get_client_statedata(client)["last_packet"]
        formatter = not_formatter["h"] + not_formatter["m"] + not_formatter["s"]
        self.log("Last timestamp for user post was {0}".format(formatter))
        return ((int(formatter) + 1) <= (current_time))
    
    def relayMessageInChat(self, message, chatid):
        pass
    
    def addUserTochat(self, obj, chatid):
        pass
    
    def removeUserFromChat(self, obj, chatid):
        pass
    
    def sendPacket(self, payload):
        if self.listener_detected:
            if "id" in payload:
                payload["listener"] = self.listener_id
            self.cl.sendPacket(payload)
        else:
            self.cl.sendPacket(payload)
    
    def on_packet(self, message):
        # CL Turbo Support
        self.listener_detected = ("listener" in message)
        self.listener_id = ""
        
        if self.listener_detected:
            self.listener_id = message["listener"]
        
        # Read packet contents
        id = message["id"]
        val = message["val"]
        if type(message["id"]) == dict:
            ip = self.cl.getIPofObject(message["id"])
            client = message["id"]
            clienttype = 0
        elif type(message["id"]) == str:
            ip = self.cl.getIPofUsername(message["id"])
            client = self.cl._get_obj_of_username(message["id"])
            clienttype = 1
        
        # Handle packet
        if "cmd" in message:    
            cmd = message["cmd"]
            
            # General networking stuff
            
            if cmd == "ping":
                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Pong"], "id": id})
            
            elif cmd == "version_chk":
                if type(val) == str:
                    
                    result, payload = self.fs.read("/Config/supported_versions.json")
                    if result:
                        payload = json.loads(payload)
                        self.versions_supported = payload["index"]
                    
                    if val in self.versions_supported:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["ObsoleteClient"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
            
            # moderator stuff
            
            elif cmd == "block":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if int(payload["secure_data"]["lvl"]) >= 2:
                                if type(val) == str:
                                    self.log("Wildcard IP blocking {0}".format(val))
                                    self.cl.blockIP(val)
                                    
                                    # Modify IP banlist file
                                    result, filecheck = self.fs.lsdir("/Jail")
                                    if result and "IPBanlist.json" in filecheck:
                                        result, payload = self.fs.read("/Jail/IPBanlist.json")
                                        if result:
                                            payload = json.loads(payload)
                                            if not str(val) in payload["wildcard"]:
                                                payload["wildcard"].append(str(val))
                                                data = json.dumps(payload)
                                                result = self.fs.write("/Jail/", "IPBanlist.json", data)
                                                if result:
                                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                                else:
                                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                            else:
                                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                        else:
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                    else:
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": id})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": id})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                    except Exception as e:
                        self.log("Error: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": id})
            
            elif cmd == "unblock":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if int(payload["secure_data"]["lvl"]) >= 2:
                                if type(val) == str:
                                    self.log("Wildcard unblocking IP {0}".format(val))
                                    self.cl.unblockIP(val)
                                    
                                    # Modify IP banlist file
                                    result, filecheck = self.fs.lsdir("/Jail")
                                    if result and "IPBanlist.json" in filecheck:
                                        if not "IPBanlist.json" in filecheck:
                                            result, payload = self.fs.read("/Jail/IPBanlist.json")
                                            if result:
                                                payload = json.loads(payload)
                                                if str(val) in payload["wildcard"]:
                                                    payload["wildcard"].remove(str(val))
                                                    data = json.dumps(payload)
                                                    self.fs.write("/Jail/", "IPBanlist.json", data)
                                    
                                    self.sendPacket({"cmd": "direct", "val": "", "id": id})
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": id})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": id})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                    except Exception as e:
                        self.log("Error: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": id})
            
            elif cmd == "kick":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if (int(payload["secure_data"]["lvl"]) >= 1) or (int(payload["secure_data"]["lvl"]) == -1):
                                if type(val) == str:
                                    if val in self.cl.getUsernames():
                                        self.sendPacket({"cmd": "direct", "val": self.cl.codes["Kicked"], "id": self.cl._get_obj_of_username(val)})
                                        time.sleep(1)
                                        self.log("Kicking {0}".format(val))
                                        self.cl.kickClient(self.cl._get_obj_of_username(val))
                                        self.sendPacket({"cmd": "direct", "val": "", "id": id})
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                    else:
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IDNotFound"], "id": id})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                    except Exception as e:
                        self.log("Error: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "clear_home":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if (int(payload["secure_data"]["lvl"]) >= 1) or (int(payload["secure_data"]["lvl"]) == -1):
                                today = datetime.now()
                                today = str(today.strftime("%d%m%Y"))
                                result = self.fs.write("/Storage/Categories/Home/", today, {"index": []})
                                self.log("{0} cleared home.".format(id))
                                self.sendPacket({"cmd": "direct", "val": "", "id": id})
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                self.create_system_message("{0} has cleared the homepage!".format(str(id)))
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                    except Exception as e:
                        self.log("Error on clear_home request: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
        
            elif cmd == "get_statedata":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if int(payload["secure_data"]["lvl"]) == 4:
                                tmp_statedata = self.cl.statedata.copy()
                                tmp_statedata.pop("ulist")
                                tmp_statedata.pop("trusted")
                                tmp_statedata.pop("gmsg")
                                tmp_statedata.pop("motd_enable")
                                tmp_statedata.pop("motd")
                                tmp_statedata.pop("secure_enable")
                                tmp_statedata.pop("secure_keys")
                                tmp_statedata["users"] = self.cl.getUsernames()
                                self.sendPacket({"cmd": "direct", "val": tmp_statedata, "id": id})
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": id})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                    except Exception as e:
                        self.log("Error at get_statedata: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": id})
            
            elif cmd == "get_user_ip":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if (int(payload["secure_data"]["lvl"]) >= 1) or (int(payload["secure_data"]["lvl"]) == -1):
                                if type(val) == str:
                                    self.sendPacket({"cmd": "direct", "val": {"username": str(val), "ip": str(self.cl.getIPofUsername(val))}, "id": id})
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": id})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": id})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                    except Exception as e:
                        self.log("Error at get_statedata: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": id})
            
            elif cmd == "get_user_data":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if (int(payload["secure_data"]["lvl"]) >= 1) or (int(payload["secure_data"]["lvl"]) == -1):
                                if type(val) == str:
                                    try:
                                        result, payload = self.secure.read_user_account(val)
                                        if result:
                                            payload["secure_data"].pop("pswd")
                                            
                                            payload2 = {
                                                "username": str(val),
                                                "payload": payload
                                            }
                                            
                                            self.log("Fetching user {0}'s account data".format(val))
                                            self.sendPacket({"cmd": "direct", "val": payload2, "id": id})
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                        else:
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                    except Exception as e:
                                        self.log("Error: {0}".format(full_stack()))
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": id})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": id})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                    except Exception as e:
                        self.log("Error at get_statedata: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": id})
            
            elif cmd == "ban":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if (int(payload["secure_data"]["lvl"]) >= 1) or (int(payload["secure_data"]["lvl"]) == -1):
                                if type(val) == str:
                                    self.log("Attempting to ban {0}".format(val))
                                    result, payload = self.secure.read_user_account(val)
                                    if result:
                                        payload["secure_data"]["banned"] = True
                                        result2, code2 = self.secure.write_user_account(val, payload)
                                        if result2:
                                            self.sendPacket({"cmd": "direct", "val": self.cl.codes["Banned"], "id": self.cl._get_obj_of_username(val)})
                                            time.sleep(1)
                                            self.log("Banned {0}, now kicking...".format(val))
                                            self.cl.kickClient(self.cl._get_obj_of_username(val))
                                            self.sendPacket({"cmd": "direct", "val": "", "id": id})
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                    else:
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                    except Exception as e:
                        self.log("Error: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "ip_ban":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if int(payload["secure_data"]["lvl"]) >= 2:
                                if type(val) == str:
                                    self.log("Attempting to IP ban {0}".format(val))
                                    
                                    userIP = self.cl.getIPofUsername(val)
                                    self.cl.blockIP(userIP)
                                    
                                    # Modify IP banlist file
                                    result, filecheck = self.fs.lsdir("/Jail")
                                    if result and "IPBanlist.json" in filecheck:
                                        result, payload = self.fs.read("/Jail/IPBanlist.json")
                                        if result:
                                            payload = json.loads(payload)
                                            if not str(val) in payload["users"]:
                                                payload["users"][str(val)] = str(userIP)
                                                
                                                if not str(userIP) in payload["wildcard"]:
                                                    payload["wildcard"].append(str(userIP))
                                                
                                                data = json.dumps(payload)
                                                result = self.fs.write("/Jail/", "IPBanlist.json", data)
                                                if result:
                                                    self.sendPacket({"cmd": "direct", "val": self.cl.codes["Blocked"], "id": self.cl._get_obj_of_username(val)})
                                                    time.sleep(1)
                                                    self.log("IP banned {0}, now kicking...".format(val))
                                                    self.cl.kickClient(self.cl._get_obj_of_username(val))
                                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                                else:
                                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                            else:
                                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                        else:
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                    else:
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                    
                                    
                                    self.sendPacket({"cmd": "direct", "val": "", "id": id})
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": id})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": id})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                    except Exception as e:
                        self.log("Error: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": id})
            
            elif cmd == "ip_pardon":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if int(payload["secure_data"]["lvl"]) >= 2:
                                if type(val) == str:
                                    self.log("Attempting to IP pardon {0}".format(val))
                                    # Modify IP banlist file
                                    result, filecheck = self.fs.lsdir("/Jail")
                                    if result and "IPBanlist.json" in filecheck:
                                        result, payload = self.fs.read("/Jail/IPBanlist.json")
                                        if result:
                                            payload = json.loads(payload)
                                            if str(val) in payload["users"]:
                                                
                                                userIP = payload["users"][str(val)]
                                                self.cl.unblockIP(userIP)
                                                
                                                del payload["users"][str(val)]
                                                
                                                if str(userIP) in payload["wildcard"]:
                                                    payload["wildcard"].remove(str(userIP))
                                                
                                                data = json.dumps(payload)
                                                result = self.fs.write("/Jail/", "IPBanlist.json", data)
                                                if result:
                                                    self.log("IP pardoned {0}.".format(val))
                                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                                else:
                                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                            else:
                                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                        else:
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                    else:
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                    
                                    
                                    self.sendPacket({"cmd": "direct", "val": "", "id": id})
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": id})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": id})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                    except Exception as e:
                        self.log("Error: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": id})
            
            elif cmd == "pardon":
                if (self.get_client_statedata(id)["authed"]):
                    try:
                        result, payload = self.secure.read_user_account(id)
                        if result:
                            self.log("RCS: {0}'s account level is {1}".format(id, str(payload["secure_data"]["lvl"])))
                            if (int(payload["secure_data"]["lvl"]) >= 1) or (int(payload["secure_data"]["lvl"]) == -1):
                                if type(val) == str:
                                    self.log("Attempting to pardon {0}".format(val))
                                    result, payload = self.secure.read_user_account(val)
                                    if result:
                                        payload["secure_data"]["banned"] = False
                                        result2, code2 = self.secure.write_user_account(val, payload)
                                        if result2:
                                            self.log("Pardoned {0}.".format(val))
                                            self.sendPacket({"cmd": "direct", "val": "", "id": id})
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                    else:
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                    except Exception as e:
                        self.log("Error: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            # Security and account stuff
            
            elif cmd == "authpswd":
                if (self.get_client_statedata(id)["authtype"] == "") or (self.get_client_statedata(id)["authtype"] == "pswd"):
                    if not self.get_client_statedata(id)["authed"]:
                        if type(val) == dict:
                            if ((("username" in val) and (type(val["username"]) == str)) and (("pswd" in val) and (type(val["pswd"]) == str))):
                                # Check username for invalid characters
                                badchars = False
                                for char in val["username"]:
                                    if not char in self.permitted_chars_username:
                                        badchars = True
                                        break
                                # Allow the username if no invalid characters
                                if not badchars:
                                    result, payload = self.secure.read_user_account(val["username"])
                                    if result:
                                        if ("banned" in payload["secure_data"]) and (payload["secure_data"]["banned"]): # User banned.
                                            self.log("{0} not authed: Account banned.".format(val["username"]))
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Banned"], "id": message["id"]})
                                        else:
                                            hashed_pswd = payload["secure_data"]["pswd"]
                                            if not hashed_pswd == "":
                                                # Check password for invalid characters
                                                badchars = False
                                                for char in str(val["pswd"]):
                                                    if not char in self.permitted_chars_username:
                                                        badchars = True
                                                        break
                                                # Allow the password if no invalid characters
                                                if not badchars:
                                                    self.modify_client_statedata(id, "authtype", "pswd")
                                                    valid_auth = self.secure.check_pswd(val["pswd"], hashed_pswd)
                                                    #print(valid_auth)
                                                    if valid_auth:
                                                        self.log("{0} is authed".format(val["username"]))
                                                        self.modify_client_statedata(id, "authtype", "pswd")

                                                        # The client is authed
                                                        self.modify_client_statedata(id, "authed", True)

                                                        payload2 = {
                                                            "mode": "auth",
                                                            "payload": {
                                                                "username": val["username"]
                                                            }
                                                        }
                                                        
                                                        # Check for clients that are trying to steal the ID and kick em' / Disconnect other sessions
                                                        if val["username"] in self.cl.getUsernames():
                                                            self.log("Detected someone trying to use the username {0} wrongly".format(val["username"]))
                                                            self.cl.kickClient(val["username"])
                                                        
                                                        # really janky code that automatically sets user ID
                                                        if self.get_client_statedata(id)["type"] != "scratch": # Prevent this from breaking compatibility with scratch clients
                                                            self.modify_client_statedata(id, "username", val["username"])
                                                            self.cl.statedata["ulist"]["usernames"][val["username"]] = id["id"]
                                                            self.sendPacket({"cmd": "ulist", "val": self.cl._get_ulist()})
                                                            self.log("{0} autoID given".format(val["username"]))
                                                        
                                                        self.sendPacket({"cmd": "direct", "val": payload2, "id": message["id"]})
                                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                                                        self.log_peak_users()
                                                    else:
                                                        self.log("{0} not authed".format(val["username"]))
                                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["PasswordInvalid"], "id": message["id"]})
                                                else:
                                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IllegalChars"], "id": message["id"]})
                                    else:
                                        if type(payload) == bool:
                                            self.log("{0} not found in accounts".format(val["username"]))
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IDNotFound"], "id": message["id"]})
                                        else:
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IllegalChars"], "id": message["id"]})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Syntax"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                    else:
                        self.log("{0} is already authed".format(id))
                        payload2 = {
                            "mode": "auth",
                            "payload": {
                                "username": val["username"]
                            }
                        }
                        self.sendPacket({"cmd": "direct", "val": payload2, "id": message["id"]})
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "get_profile":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    if clienttype == 1:
                        if type(val) == str:
                            result, payload = self.secure.read_user_account(val)
                            if result: # Format message for meower
                                payload["lvl"] = payload["secure_data"]["lvl"] # Make the user's level read-only
                                payload.pop("secure_data") # Remove the user's secure data
                                if str(val) != str(id): # Purge sensitive data if the specified ID isn't the same
                                    payload.pop("user_settings") # Remove user's settings
                                payload["user_id"] = str(val) # Report user ID for profile
                                payload = {
                                    "mode": "profile",
                                    "payload": payload
                                }
                                self.log("{0} fetching profile {1}".format(id, val))
                            if result:
                                self.sendPacket({"cmd": "direct", "val": payload, "id": message["id"]})
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IDNotFound"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "gen_account":
                if (((self.get_client_statedata(id)["authtype"] == "") and (not self.get_client_statedata(id)["authed"])) or ((self.get_client_statedata(id)["authtype"] == "2fa") and (self.get_client_statedata(id)["authed"]))):
                    # Check username for invalid characters
                    badchars = False
                    for char in str(id):
                        if not char in self.permitted_chars_username:
                            badchars = True
                            break
                    # Allow the username if no invalid characters
                    if not badchars:
                        # Generate the user account
                        result, code = self.secure.gen_user_account(id)
                        if result and code:
                            
                            # Since the account was just created, add auth info, if the account was made using a password then generate hash and store it
                            if (not self.get_client_statedata(id)["authtype"] == "") or (not self.get_client_statedata(id)["authtype"] == "2fa"):
                                if type(val) == str:
                                    
                                    # Check password for invalid characters
                                    badchars = False
                                    for char in str(val):
                                        if not char in self.permitted_chars_username:
                                            badchars = True
                                            break
                                    # Allow the password if no invalid characters
                                    if not badchars:
                                        # Generate a hash for the password
                                        hashed_pswd = self.secure.create_pswd(val)
                                        
                                        # Store the hash in the account's file
                                        result, payload = self.secure.read_user_account(id)
                                        
                                        if result:
                                            payload["secure_data"]["pswd"] = hashed_pswd
                                            result2, code2 = self.secure.write_user_account(id, payload)
                                            if result2:
                                                payload2 = {
                                                    "mode": "auth",
                                                    "payload": ""
                                                }
                                                
                                                # The client is authed
                                                self.log("{0} is authed w/ new account generated".format(id))
                                                self.modify_client_statedata(id, "authed", True)
                                                
                                                self.sendPacket({"cmd": "direct", "val": payload2, "id": message["id"]})
                                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                                            else:
                                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                                        else:
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                                    else:
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IllegalChars"], "id": message["id"]})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Syntax"], "id": message["id"]})
                            
                        else:
                            if (not result) and code:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IDExists"], "id": message["id"]})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IllegalChars"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "update_config":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    if clienttype == 1:
                        if type(val) == dict:
                            result, payload = self.secure.read_user_account(id)
                            if result: # Format message for meower
                                for config in val:
                                    if config in payload:
                                        if (not "lvl" in config) or (not "pswd" in config):
                                            payload[config] = val[config]
                                result2, payload2 = self.secure.write_user_account(id, payload)
                                if result2:
                                    payload3 = {
                                        "mode": "cfg",
                                        "payload": ""
                                    }
                                    self.log("{0} Updating their config".format(id))
                                    self.sendPacket({"cmd": "direct", "val": payload3, "id": message["id"]})
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IDNotFound"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            # Data management stuff
            
            elif cmd == "search_user_posts":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    if type(val) == dict:
                        if ("query" in val) and (type(val["query"]) == str):
                            query_return = []
                            
                            # Read directory for listing of all posts starting with the query request
                            for file in os.listdir(self.fs.dirpath + "/Storage/Posts"):
                                check = file.split("-")
                                if check[0] == val["query"]:
                                    query_return.append(str(file))
                            
                            query_return.reverse()
                            # Get number of pages
                            if len(query_return) == 0:
                                pages = 0
                            else:
                                if (len(query_return) % 25) == 0:
                                    if (len(query_return) < 25):
                                        pages = 1
                                    else:
                                        pages = (len(query_return) // 25)
                                else:
                                    pages = (len(query_return) // 25)+1
                            
                            # Request handler
                            if ("page" in val) and (type(val["page"]) == int):
                                if (not val["page"] > pages) and (not val["page"] <= 0):
                                    print((val["page"]*25)-25)
                                    print(val["page"]*25)
                                    query_return = query_return[((val["page"]*25)-25):val["page"]*25]
                                    
                                    query_convert = ""
                                    for item in query_return:
                                        query_convert = str(query_convert + str(item) + ";")
                                    
                                    query_response = {
                                        "query": val["query"],
                                        "index": query_convert,
                                        "page#": val["page"]
                                    }
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Syntax"], "id": id})
                                    return
                                
                            else:
                                query_response = {
                                    "query": val["query"],
                                    "pages": pages
                                }

                            self.sendPacket({"cmd": "direct", "val": query_response, "id": id})
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Syntax"], "id": id})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": id})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": id})
            
            elif cmd == "delete_post":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    if type(val) == str:
                        self.log("Looking for post ID {0}...".format(val))
                        
                        status, payload = self.fs.lsdir("Storage/Posts/")
                        
                        if status:
                            if val in payload:
                                result, payload = self.fs.read("/Storage/Posts/" + val)
                                payload = json.loads(payload)
                                self.log("Marking post {0} as deleted...".format(val))
                                payload["isDeleted"] = True
                                result2 = self.fs.write("/Storage/Posts/", val, payload)
                                if result2:
                                    self.sendPacket({"cmd": "direct", "val": {"mode": "delete", "id": val}})
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IDNotFound"], "id": id})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                        
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": id})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": id})
            
            # General chat stuff
            
            elif cmd == "get_chat_list":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    if not id in self.fs.lsdir("Storage/Categories/Chats/"):
                        result = self.fs.mkdir("Storage/Categories/Chats/{0}".format(str(id)))
                    
                    if type(val) == dict:
                        query_return = []
                        
                        # Read directory for listing of all posts starting with the query request
                        result, query_return = self.fs.lsdir("Storage/Categories/Chats/{0}".format(str(id)))
                        if result:
                            query_return.reverse()
                            
                            # Get number of pages
                            if len(query_return) == 0:
                                pages = 0
                            else:
                                if (len(query_return) % 5) == 0:
                                    if (len(query_return) < 5):
                                        pages = 1
                                    else:
                                        pages = (len(query_return) // 5)
                                else:
                                    pages = (len(query_return) // 5)+1
                            
                            # Request handler
                            if ("page" in val) and (type(val["page"]) == int):
                                if (not val["page"] > pages) and (not val["page"] <= 0):
                                    query_return = query_return[((val["page"]*5)-5):val["page"]*5]
                                    
                                    query_convert = ""
                                    for item in query_return:
                                        query_convert = str(query_convert + str(item) + ";")
                                    
                                    query_response = {
                                        "index": query_convert,
                                        "page#": val["page"]
                                    }
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Syntax"], "id": id})
                                    return
                                
                            else:
                                query_response = {
                                    "pages": pages
                                }

                            self.sendPacket({"cmd": "direct", "val": query_response, "id": id})
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": id})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": id})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": id})
            
            elif cmd == "get_chat_data":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    pass
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "create_chat":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    if type(val) == str:
                        
                        if not id in self.fs.lsdir("Storage/Categories/Chats/"):
                            result = self.fs.mkdir("Storage/Categories/Chats/{0}".format(str(id)))
                        
                        if (len(val) > 0) and (len(val) <= 20):
                            if not val in self.fs.lsdir("Storage/Categories/Chats/{0}".format(str(id))):
                                result = self.fs.mkdir("Storage/Categories/Chats/{0}/{1}".format(str(id), str(val)))
                                if result:
                                    result = self.fs.write(("Storage/Categories/Chats/{0}/{1}/".format(str(id), str(val))), "{0}.json".format(str(val)), json.dumps({"index": []}))
                                    if result:
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                                    else:
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IDExists"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["TooLarge"], "id": message["id"]})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "get_peak_users":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    payload = {
                        "mode": "peak",
                        "payload": self.peak_users_logger
                    }
                    self.sendPacket({"cmd": "direct", "val": payload, "id": message["id"]})
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "set_chat_state":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    if ("state" in val) and ("chatid" in val):
                        if (type(val["state"]) == int) and (type(val["chatid"]) == str):
                            state = {
                                "state": val["state"]
                            }
                            if clienttype == 0:
                                state["u"] = ""
                            else:
                                state["u"] = id
                            
                            state["chatid"] = val["chatid"]
                                
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                            self.log("{0} modifying chat ID {1} state to {2}".format(id, val["chatid"], val["state"]))
                            self.sendPacket({"cmd": "direct", "val": state})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Syntax"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "post_chat":
                print('test')
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    if type(val) == dict:
                        if ("p" in val) and ("chatid" in val):
                            if (type(val["p"]) == str) and (type(val["chatid"]) == str):
                                if (not len(val["p"]) > 100):
                                    if self.check_for_spam(id):
                                        # Check for invalid characters
                                        badchars = False
                                        for char in val["p"]:
                                            if not char in self.permitted_chars_post:
                                                badchars = True
                                                break
                                        # Allow the message to go through if no characters are detected to be invalid
                                        if not badchars:
                                            try:
                                                result, payload = self.secure.read_user_account(id)
                                                if int(payload["secure_data"]["lvl"]) >= 0:
                                                    today = datetime.now()
                                                    
                                                    # Run word filter against post data
                                                    post = profanity.censor(val["p"])
                                                    
                                                    post_w_metadata = {
                                                        "t": {
                                                            "mo": (datetime.now()).strftime("%m"),
                                                            "d": (datetime.now()).strftime("%d"),
                                                            "y": (datetime.now()).strftime("%Y"),
                                                            "h": (datetime.now()).strftime("%H"),
                                                            "mi": (datetime.now()).strftime("%M"),
                                                            "s": (datetime.now()).strftime("%S"),
                                                        },
                                                        "state": 2,
                                                        "p": post,
                                                        "chatid": val["chatid"]
                                                    }
                                                    if clienttype == 0:
                                                        post_w_metadata["u"] = ""
                                                    else:
                                                        post_w_metadata["u"] = id
                                                    
                                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                                                    self.sendPacket({"cmd": "direct", "val": post_w_metadata})
                                                else:
                                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": message["id"]})
                                            except Exception as e:
                                                self.log("Error: {0}".format(full_stack()))
                                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                                        else:
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IllegalChars"], "id": message["id"]})
                                    else:
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["RateLimit"], "id": message["id"]})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["TooLarge"], "id": message["id"]})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Syntax"], "id": message["id"]})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Syntax"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "post_home":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    if type(val) == str:
                        if (not len(val) > 360):
                            if self.check_for_spam(id):
                                # Check for invalid characters
                                badchars = False
                                for char in val:
                                    if not char in self.permitted_chars_post:
                                        badchars = True
                                        break
                                # Allow the message to go through if no characters are detected to be invalid
                                if not badchars:
                                    try:
                                        result, payload = self.secure.read_user_account(id)
                                        if result:
                                            if int(payload["secure_data"]["lvl"]) >= 0:
                                                today = datetime.now()
                                                # Generate a post ID
                                                post_id = str(today.strftime("%d%m%Y%H%M%S")) 
                                                if clienttype == 0:
                                                    post_id = "-" + post_id
                                                else:
                                                    post_id = id + "-" + post_id
                                                
                                                # Run word filter against post data
                                                post = profanity.censor(val)
                                                
                                                # Attach metadata to post
                                                post_w_metadata = {
                                                    "t": {
                                                        "mo": (datetime.now()).strftime("%m"),
                                                        "d": (datetime.now()).strftime("%d"),
                                                        "y": (datetime.now()).strftime("%Y"),
                                                        "h": (datetime.now()).strftime("%H"),
                                                        "mi": (datetime.now()).strftime("%M"),
                                                        "s": (datetime.now()).strftime("%S"),
                                                    },
                                                    "p": post,
                                                    "post_origin": "home",
                                                    "isDeleted": False
                                                }
                                                if clienttype == 0:
                                                    post_w_metadata["u"] = ""
                                                else:
                                                    post_w_metadata["u"] = id
                                                
                                                # Read back current homepage state (and create a new homepage if needed)
                                                status, payload = self.get_indexer(location="/Categories/Home/")
                                                
                                                # Check status of homepage
                                                if status != 0:
                                                    # Update the current homepage
                                                    result = self.update_indexer(post_id, location="/Categories/Home/")
                                                    
                                                    if result:
                                                        # Store the post
                                                        result2 = self.fs.write("/Storage/Posts", post_id, post_w_metadata)
                                                        if result2:
                                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                                                            
                                                            # Broadcast the post to all listening clients
                                                            relay_post = post_w_metadata
                                                            relay_post["mode"] = 1
                                                            relay_post["post_id"] = str(post_id)
                                                            #print(relay_post)
                                                            self.log("{0} posting home message {1}".format(id, post_id))
                                                            self.sendPacket({"cmd": "direct", "val": relay_post})
                                                        else:
                                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                                                    else:
                                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                                                else:
                                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": id})
                                            else:
                                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["MissingPermissions"], "id": message["id"]})
                                        else:
                                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                    except Exception as e:
                                        self.log("Error: {0}".format(full_stack()))
                                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": id})
                                else:
                                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["IllegalChars"], "id": message["id"]})
                            else:
                                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["RateLimit"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["TooLarge"], "id": message["id"]})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "get_post":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                    if type(val) == str:
                        # Check for posts in storage
                        result, payload = self.fs.read("/Storage/Posts/" + val)
                        
                        if result: # Format message for meower
                            # Temporarily convert the JSON string to Dict to add the post ID data to it
                            tmp_payload = json.loads(payload)
                            tmp_payload["post_id"] = val
                            payload = json.dumps(tmp_payload)
                            
                            if ("isDeleted" in json.loads(payload)) and (json.loads(payload)["isDeleted"]):
                                payload = {
                                    "mode": "post",
                                    "isDeleted": True
                                }
                            
                            else:
                                payload = {
                                    "mode": "post",
                                    "payload": json.loads(payload),
                                    "isDeleted": False
                                }
                            
                            
                        if result:
                            self.log("{0} getting home message {1}".format(id, tmp_payload["post_id"]))
                            self.sendPacket({"cmd": "direct", "val": payload, "id": message["id"]})
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                        else:
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                    else:
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Datatype"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            elif cmd == "get_home":
                if (self.get_client_statedata(id)["authed"]) or (self.ignoreUnauthedBlanks):
                
                    try:
                        status, payload = self.get_indexer(location="/Categories/Home/", truncate=True, convert=True, mode="Latest")
                        
                        if status != 0: # Format message for meower
                            payload = {
                                "mode": "home",
                                "payload": payload
                            }
                        self.log("{0} getting home index".format(id))
                        
                        if status == 0: # Home error
                            self.log("Error while generating homepage")
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                        elif status == 1: # Home was generated
                            self.sendPacket({"cmd": "direct", "val": payload, "id": message["id"]})
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                        elif status == 2: # Home already generated
                            self.sendPacket({"cmd": "direct", "val": payload, "id": message["id"]})
                            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["OK"], "id": message["id"]})
                    except Exception as e:
                        self.log("Error on get_home request: {0}".format(full_stack()))
                        self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["InternalServerError"], "id": message["id"]})
                else:
                    self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Refused"], "id": message["id"]})
            
            else:
                self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Invalid"], "id": message["id"]})
        else:
            self.sendPacket({"cmd": "statuscode", "val": self.cl.codes["Syntax"], "id": message["id"]})
        
        # Rate limiter
        today = datetime.now()
        self.modify_client_statedata(client, "last_packet", {
            "h": today.strftime("%H"),
            "m": today.strftime("%M"),
            "s": today.strftime("%S")
        })

if __name__ == "__main__":
    meower(debug = False, ignoreUnauthedBlanks = False) # Runs the server