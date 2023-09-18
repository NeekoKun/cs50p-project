from ctypes import c_long, c_wchar_p, c_ulong, c_void_p
from peer import Peer
import threading
import platform
import logging
import ctypes
import sys
import os

gHandle = ctypes.windll.kernel32.GetStdHandle(c_long(-11))
incoming = []
unread = 0
arrest_sequence = ":q!"

def login(peer: Peer) -> None:
    username = input("Enter username: ")
    password = input("Enter password: ")
    granter = input("Enter granter IPv4 address: ")

    peer.login(username, password, granter)


def move(x: int, y: int) -> None:
    """Move terminal cursor to (x, y) position"""
    value = x + (y << 16)
    ctypes.windll.kernel32.SetConsoleCursorPosition(gHandle, c_ulong(value))


def addstr(string: str) -> None:
    """Write string"""
    ctypes.windll.kernel32.WriteConsoleW(gHandle, c_wchar_p(string), c_ulong(len(string)), c_void_p(), None)


def signup(peer: Peer) -> None:
    peer.signup("NeekoLinux", "Pollo", "192.168.1.10")
    return
    username = input("Enter username: ")
    password = input("Enter password: ")
    granter = input("Enter granter IPv4 address: ")

    peer.signup(username, password, granter)


def create_network(peer: Peer) -> None:
    peer.create_network("NeekoKunAdmin", "Palle",
                        "192.168.1.10", "None", "None")
    return
    username = input("Enter username: ")
    password = input("Enter password: ")

    ip = input("Enter your IPv4 address in the network for the forum: ")

    sign = "None"
    encrypting = "None"

    if input("Use asymmetric signing (y/n): ").lower() == "y":
        sign = "asymmetric"

    if input("Use asymmetric encryption (y/n): ").lower() == "y":
        encrypting = "asymmetric"

    peer.create_network(username, password, ip, sign, encrypting)


def display_messages() -> None:
    if platform.system() == "Windows":
        os.system("CLS")
    if platform.system() == "Linux":
        os.system("clear")

    for message in incoming:
        print(message)

def log_messages(peer) -> None:
    while True:
        if len(peer.to_read) > 0:
            incoming.append(peer.read())
            unread += 1


def settings(peer: Peer) -> None:
    print("Current Settings:")
    print("")
    print(f"     Arrest Sequence: - : {arrest_sequence}")
    print("")
    print(f"     Username: -------- : {peer.username}")

    setting = input("Which setting do you want to configure?\n").tolower()
    match setting:
        case "":
            return
        case "arrest sequence":
            arrest_sequence = input("Input new arrest sequence: ")
        case "username":
            logging.debug("Username config not implemented, feature supported as PoC.")
            input("Input new username: ")


def main():
    logging.basicConfig(level=logging.INFO, filename="project.log")
    peer = Peer()

    print("1-Log In\n2-Sign Up\n3-Create Network\n0-Close\n")
    match input(""):
        case "1":
            login(peer)
        case "2":
            signup(peer)
        case "3":
            create_network(peer)
        case "0":
            sys.exit()
        case _:
            raise NotImplementedError

    logging_messages = threading.Thread(target=log_messages, args=(peer,))
    logging_messages.daemon = True
    logging_messages.start()

    if platform.system() == "Windows":
        os.system("CLS")
    if platform.system() == "Linux":
        os.system("clear")

    while True:
        match input(f"Connected to network.\n\n\nChose and option:\n\n1 - Send Private Message\n2 - Send Broadcast Message\n3 - Read received messages\n0 - Settings\n\n"):
            case "1":
                raise NotImplementedError("Private messages have not yet been implemented")
            case "2":
                print("Arrest sequence: "+arrest_sequence+"\nYou may change the arrest sequence in the settings menu.")
                rows = []
                while True:
                    inp = input(f">")
                    if inp == arrest_sequence: break
                    rows.append(inp)
                message = "\n".join(rows)
                peer.send(message, -1)
            case "3":
                move(0, 0)
                display_messages()
                inp = input("Press enter to exit...")
            case "0":
                settings(peer)
            case _:
                raise NotImplementedError


        if platform.system() == "Windows":
            os.system("CLS")
        if platform.system() == "Linux":
            os.system("clear")

    peer.close()


if __name__ == '__main__':
    main()
