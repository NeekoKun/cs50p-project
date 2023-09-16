from cryptography.fernet import Fernet
from signer import SignerEngine
import threading
import hashlib
import logging
import socket
import base64
import csv


class Peer:
    def __init__(self, encryption="None", signature="None"):
        self.id = 0
        self.devices = []               # List of every device in the network, complete of IP, port, key and signature
        self.neighbors = []             # List of actually connected devices to self
        self.connection_threads = []    # List of connection threads
        self.to_send = []               # Queue of message to be sent. Format: (ip, message)
        self.queue = []
        self.running = True
        self.granting = False
        self.encryption = False
        self.signature = False
        self.stop_event = threading.Event()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        
        self.logger.info("Setting encryption method")
        self.set_encryption(encryption)
        self.set_signature(signature)

    def create_network(self, username: str, password: str, ip: str, signature: str, encryption: str) -> None:
        self.username = username
        self.password = hashlib.sha256(password.encode("utf-8")).hexdigest()
        self.logger.debug("Password hashed")
        
        self.logger.debug("Writing credentials to 'credentials.csv'")
        with open("credentials.csv", "w") as file:
            writer = csv.writer(file)
            writer.writerow((self.username, self.password))
            self.logger.debug(f"Written {self.username},{self.password} to 'credentials.csv'")
        
        
        self.logger.debug("Setting signature method")
        self.set_signature(signature)
        self.logger.debug("Setting encryption method")
        self.set_encryption(encryption)
        
        self.devices.append({"ip": ip, "port": 44440})
        
        self.grant()

    def set_encryption(self, type: str) -> None:
        try:
            if self.encryption:
                if type == "None":
                    self.encryption = False
                    del self.encryption_type
                else:
                    self.encryption_type = type
            else:
                if type != "None":
                    self.encryption = True
                    self.encryption_type = type
                else:
                    
                    pass
        except:
            self.logger.error(f"Encryption type ({type}) not supported, falling back to default encryption type")

    def set_signature(self, type: str) -> None:
        try:
            if self.signature:
                if type == "None":
                    self.signature = False
                    
                    del self.signer
                    del self.public_sign
                    del self.signature_type
                elif type == "symmetric" or type == "asymmetric":
                    self.signature_type = type
                else:
                    raise NotImplementedError
            else:
                if type == "symmetric" or type == "asymmetric":
                    self.signature = True
                    self.signature_type = type
                elif type != "None":
                    raise NotImplementedError
            if type == "asymmetric":
                self.signer = SignerEngine(self.password)
                self.public_sign = self.signer.get_public_key()
                
        except NotImplementedError:
            self.logger.warning(f"Signature type {type} has not been implementer, falling back to None")
            
            if self.signature:
                del self.signature_type
                del self.public_sign
                del self.signer
                self.signature = False

    def get_device_by_arg(self, arg: str, target) -> dict:
        for device in self.devices:
            if device[arg] == target:
                return device

        return None

    def processed_message(self, message: bytes, id: int) -> bytes:
        if self.encryption:
            self.logger.debug("Setting up cipher for encryption/decryption of message")
            processed_key = base64.urlsafe_b64encode(hashlib.sha256(self.devices[id]["key"].encode("utf-8")).digest())
            cipher = Fernet(processed_key)
            del processed_key
        
        if id != self.id:
            self.logger.debug("Processing incoming message...")
            if self.encryption:
                self.logger.debug("Decrypting message...")
                message = cipher.decrypt(message)
                
            if self.signature:
                self.logger.debug("Validating message signature...")
                
                if type(message) is bytes:
                    message = message.decode("utf-8")
                
                message, sign = message.split(" -|- ")
                
                if self.signer.verify_sign(self.devices[id]["sign"], message, sign):
                    self.logger.debug("Signature verified successfully")
                else:
                    self.logger.info("Failed to verify signature")
                    raise ValueError("Invalid signature")
            else:
                message = message.decode("utf-8")
            
        else:
            self.logger.debug("Processing outgoing message...")
            if self.signature:
                self.logger.debug("Signing message...")
                sign = self.signer.sign(message)
                message += " -|- " + sign
                self.logger.debug("Message signed with ' -|- ' separator")
            
            if self.encryption:
                self.logger.debug("Encrypting message...")
                
                if type(message) == str:
                    message = message.encode("utf-8")
                
                message = cipher.encrypt(message)
                self.logger.debug("Message encrypted succefully")
            
        if type(message) == str:
            message.encode("utf-8")
            
        return message

    def send_message_single(self, ip: str, port: int, msg: str) -> None:
        self.logger.debug(f"Opening connection to send single message")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        message = self.processed_message(msg, self.id)

        self.logger.debug(f"Connecting to {ip}:{port}")
        s.connect((ip, port))
        self.logger.debug("Sending message")
        s.send(message)

        if s.recv(1024) == "yes":
            self.logger.debug("Message sent succesfully")
        else:
            self.logger.waring(f"Problem sending message to {ip}:{port}")

        self.logger.debug(f"Closing connection with {ip}:{port}")
        s.close()

    def add_credentials(self, creds: tuple) -> None:
        with open("credentials.csv", "a", newline='') as csvfile:
            writer = csv.writer(csvfile)
            self.logger.debug(f"Writing {creds} to 'credentials.csv'")
            writer.writerow(creds)

    def check_login_credentials(self, connection: socket.socket, addr: tuple) -> bool:
        self.logger.debug("Receiving and decoding username")
        receiving = connection.recv(1024).decode("utf-8")
        
        with open("credentials.csv", "r") as csvfile:
            credentials = csv.reader(csvfile)
            
            for i in credentials:
                if len(i) == 2 and i[0] == receiving:
                    _, password = i
                    self.logger.debug("Username existing, sending confimation")
                    connection.send("yes".encode("utf-8"))
                    break
            else:
                self.logger.info(f"{addr[0]} tried to login with wrong username: {receiving}")
                connection.send("no".encode("utf-8"))
            
            if (pwd := connection.recv(1024).decode("utf-8")) == password:
                self.logger.debug("Correct password, sending confirmation")
                connection.send("yes".encode("utf-8"))
            else:
                self.logger.info(f"{addr[0]} tried to login with wrong password: {pwd}")
                connection.send("no".encode("utf"))
    
    def check_signup_credentials(self, connection: socket.socket, addr: tuple, username: str) -> bool:
        with open("credentials.csv", "r") as csvfile:
            credentials = csv.reader(csvfile)
            
            for i in credentials:
                if len(i) == 2 and i[0] == username:
                    self.logger.info(f"{addr[0]} tried to sign up with an already existing username: {username}")
                    connection.send("no".encode("utf-8"))
                    return False
        
        self.logger.debug(f"Username {username} available, sending confirmation")
        connection.send("yes".encode("utf-8"))
        
        password = connection.recv(1024).decode("utf-8")
        
        self.logger.debug("Password received, appending credentials to csv file")
        self.add_credentials((username, password))

        return True

    def settings(self) -> str:
        if self.encryption and self.signature:
            self.logger.debug("Settings for encryption and signature")
            return f"{self.encryption_type}|{self.signature_type}"
        elif self.encryption:
            self.logger.debug("Settings for encryption")
            return f"{self.encryption_type}|None"
        elif self.signature:
            self.logger.debug("Settings for signature")
            return f"None|{self.signature_type}"
        else:
            self.logger.debug("Neither encryption nor signature settings are selected")
            return "None|None"
    
    def str_devices(self) -> str:
        message = []
        
        for i in self.devices:
            b = []
            for j in i.values():
                b.append(str(j))
            message.append("|".join(b))
        
        return " -|- ".join(message)
    
    def handle_login(self, connection: socket.socket, address: tuple) -> None:
        connection.send("ok".encode("utf-8"))
        
        self.logger.debug("Checking for login credentials...")
        if not self.check_login_credentials(connection, address):
            self.logger.info("Failed to pass login check, aborting connection")
            return
        
        new_device = {}
        new_device["ip"] = address[0]
        new_device["port"] = address[1]           

        
        if connection.recv(1024).decode("utf-8") == "Settings?":
            self.logger.debug("Sending settings")
            connection.send(self.settings().encode("utf-8"))
        
        self.devices.append(new_device)
        
        if connection.recv(1024).decode("utf-8") == "Devices?":
            self.logger.debug("Sending devices")
            connection.send(self.str_devices().encode("utf-8"))

        if self.encryption:
            self.logger.debug("Saving key for encryption of new device")
            self.devices[-1]["key"] = connection.recv(1024).decode("utf-8")
            connection.send("yes".encode("utf-8"))
        
        if self.signature:
            self.logger.debug("Saving signature of new device")
            self.device[-1]["sign"] = connection.recv(1024).decode("utf-8")
            connection.send("yes".encode("utf-8"))

    def handle_signup(self, connection: socket.socket, address: tuple) -> None:
        connection.send("yes".encode("utf-8"))
        
        username = connection.recv(1024).decode("utf-8")
        self.logger.debug("Checking for signup credentials...")
        if not self.check_signup_credentials(connection, address, username):
            self.logger.info("Failed to pass signup check, aborting connection")
            return
        
        new_device = {}
        new_device["ip"] = address[0]
        new_device["port"] = address[1]
        
        if connection.recv(1024).decode("utf-8") == "Settings?":
            self.logger.debug("Sending settings")
            connection.send(self.settings().encode("utf-8"))
        
        self.devices.append(new_device)
            
        if connection.recv(1024).decode("utf-8") == "Devices?":
            self.logger.debug("Sending devices")
            strdevs = self.str_devices()
            print(strdevs)
            connection.send(self.str_devices().encode("utf-8"))
            
        if self.encryption:
            self.logger.debug("Saving key for encryption of new device")
            self.devices[-1]["key"] = connection.recv(1024).decode("utf-8")
            connection.send("yes")
        
        if self.signature:
            self.logger.debug("Saving signature of new device")
            self.devices[-1]["sign"] = connection.recv(1024).decode("utf-8")
            connection.send("yes")

    def grant(self, granter=True) -> None:
        if granter and not self.granting:
            self.logger.debug("Generating thread to listen for join requests")
            self.granting = True
            self.granter_thread = threading.Thread(target=self.listen_as_granter)
            self.granter_thread.start()
        
        if not granter and self.granting:
            self.granting = False
            self.granter_thread._stop()

    def listen_as_granter(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        s.bind(("0.0.0.0", 44440))
        s.listen()
        
        self.logger.debug("Waiting for connection as granter...")
        conn, addr = s.accept()
        
        match conn.recv(1024).decode("utf-8"):
            case "login":
                conn.send("yes".encode("utf-8"))
                self.logger.debug(f"Starting login procedure on {addr[0]}")
                self.handle_login(conn, addr)
                self.logger.debug(f"Login procedure succeded on {addr[0]}")
            case "signup":
                conn.send("yes".encode("utf-8"))
                self.logger.debug(f"Starting signup procedure on {addr[0]}")
                self.handle_signup(conn, addr)
                self.logger.debug(f"Signup procedure succeded on {addr[0]}")
            case _:
                conn.close()
                self.logger.info("Connection aborted as neither login nor signup request were received")
             
    def get_devices(self, string: str) -> list:
        devices = string.split(" -|- ")
        
        result = []
        
        for i in devices:
            new_device = {}
            new_device["ip"] = i.split("|")[0]
            new_device["port"] = int(i.split("|")[1])
            
            if self.encryption:
                new_device["key"] = i.split("|")[2]
                
                if self.signature:
                    new_device["sign"] = i.split("|")[3]
            else:
                if self.signature:
                    new_device["sign"] = i.split("|")[2]
            
            result.append(new_device)
        
        return result

    def verify_credentials(self, username: str, password: str, s: socket.socket) -> bool:
        s.send(username.encode("utf-8"))        
        
        match s.recv(1024).decode("utf-8"):
            case "yes":
                pass
                
            case "no":
                return False
                
            case _:
                raise NotImplementedError
        
        s.send(password.encode("utf-8"))
        
        match s.recv(1024).decode("utf-8"):
            case "yes":
                pass
                
            case "no":
                return False
                
            case _:
                raise NotImplementedError
            
        return True

    def login(self, username: str, password: str, granter: str) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        password = hashlib.sha256(password.encode("utf-8")).hexdigest()
        
        s.connect((granter, 44440))
        
        s.send("login".encode("utf-8"))

        if s.recv(1024).decode("utf-8") != "yes":
            self.logging.error("Login failed")
            raise ConnectionError(f"Could not connect to {granter}")

        if self.verify_credentials(username, password, s):
            self.username = username
            self.password = password
        else:
            raise ValueError("Invalid username or password.")
        
        # Ask for and apply settings
        
        s.send("Settings?".encode("utf-8"))
        response = s.recv(1024).decode("utf-8")
        
        self.set_encryption(response.split("|")[0])
        self.set_signature(response.split("|")[1])
        
        # Ask for devices list
        
        s.send("Devices?".encode("utf-8"))
        self.devices = self.get_devices(s.recv(1024).decode("utf-8"))
        self.id = len(self.devices) - 1

        # Send encryption key
        if self.encryption:
            if self.encryption_type == "symmetric":
                s.send(self.key.encode("utf-8"))
            else:
                s.send(self.public_key.encode("utf-8"))
        
        # Send signing key
        if self.signature and s.recv(1024).decode("utf-8") == "yes":
            if self.signature_type == "symmetric":
                raise NotImplementedError("Symmetric signing has not yet been implemented.")
            else:
                s.send(self.public_sign.encode("utf-8"))
        
        s.recv(1024)
        s.close()
    
    def signup(self, username: str, password: str, granter: str) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        password = hashlib.sha256(password.encode("utf-8")).hexdigest()
        
        s.connect((granter, 44440))
        
        s.send("signup".encode("utf-8"))
        
        if s.recv(1024).decode("utf-8") != "yes":
            self.logger.error(f"Failed to sign up to {granter}")
            raise ConnectionError("Could not sign up")
        
        s.send(username.encode("utf-8"))
        
        if s.recv(1024).decode("utf-8") != "yes":
            return
        
        self.username = username
        s.send(password.encode("utf-8"))
        
        if s.recv(1024).decode("utf-8") != "yes":
            return
        
        self.password = password
        self.add_credentials((username, password))
        
        # Ask for and apply settings
        
        s.send("Settings?".encode("utf-8"))
        response = s.recv(1024).decode("utf-8")
        
        self.set_encryption(response.split("|")[0])
        self.set_signature(response.split("|")[1])
        
        # Ask for devices list
        
        s.send("Devices?".encode("utf-8"))
        self.devices = self.get_devices(s.recv(1024).decode("utf-8"))

        self.id = len(self.devices) - 1

        # Send encryption key
        if self.encryption:
            if self.encryption_type == "symmetric":
                s.send(self.key.encode("utf-8"))
            else:
                s.send(self.public_key.encode("utf-8"))
        
        # Send signing key
        if self.signature and s.recv(1024).decode("utf-8") == "yes":
            if self.signature_type == "symmetric":
                raise NotImplementedError("Symmetric signing has not yet been implemented.")
            else:
                s.send(self.public_sign.encode("utf-8"))
        
        s.recv(1024)
        s.close()

    def close(self) -> None:
        self.stop_event.set()
        print("Exiting...")
        return

    def connect(self, device):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((device["ip"], device["port"]))

        while not self.stop_event.is_set():
            if len(self.to_send) > 0 and (self.to_send[0]["ip"] == device["ip"] or self.to_send[0]["ip"].split(".")[-1] == "255"):
                s.send(self.processed_message(self.to_send[1], device["key"]))

        s.close()