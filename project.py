from peer import Peer
import threading
import logging
import time
import sys

def login(peer: Peer) -> None:
    username = input("Enter username: ")
    password = input("Enter password: ")
    granter = input("Enter granter IPv4 address: ")
    
    peer.login(username, password, granter)


def signup(peer: Peer) -> None:
    peer.signup("Neeko", "Palle", "192.168.1.10")
    #username = input("Enter username: ")
    #password = input("Enter password: ")
    #granter = input("Enter granter IPv4 address: ")
    #
    #peer.signup(username, password, granter)


def create_network(peer: Peer) -> None:
    peer.create_network("NeekoKun", "Password", "192.168.1.10", "None", "None")
    #username = input("Enter username: ")
    #password = input("Enter password: ")
    #
    #ip = input("Enter your IPv4 address in the network for the forum: ")
    #
    #sign = "None"
    #encrypting = "None"
    #
    #if input("Use asymmetric signing (y/n): ").lower() == "y":
    #    sign = "asymmetric"
    #
    #if input("Use asymmetric encryption (y/n): ").lower() == "y":
    #    encrypting = "asymmetric"
    #
    #peer.create_network(username, password, ip, sign, encrypting)


def main():
    logging.basicConfig(level=logging.INFO)
    peer = Peer()
    
    print("1-Login\n2-Sign up\n3-Create network\n0-close\n")
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

    print(threading.enumerate())
    
    while True:
        print("\r"+str(peer.devices), end="")
        time.sleep(5)

if __name__ == '__main__':
    main()