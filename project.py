from peer import Peer
import threading
import platform
import logging
import sys
import os

def login(peer: Peer) -> None:
    username = input("Enter username: ")
    password = input("Enter password: ")
    granter = input("Enter granter IPv4 address: ")
    
    peer.login(username, password, granter)


def signup(peer: Peer) -> None:
    username = input("Enter username: ")
    password = input("Enter password: ")
    granter = input("Enter granter IPv4 address: ")
    
    peer.signup(username, password, granter)


def create_network(peer: Peer) -> None:
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


def main():
    logging.basicConfig(level=logging.INFO, filename="project.log")
    messages = []
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

    while True:
        inp = input(f"{len(peer.to_send)}>")
        if inp == "":
            break
        peer.send(inp, -1)
        
        if platform.system() == "Windows":
            os.system("CLS")
        if platform.system() == "Linux":
            os.system("clear")
        
        print(threading.enumerate())
        
        while True:
            try:
                messages.append(peer.read())
            except IndexError:
                break
            
        for msg in messages:
            print(msg)

        
    peer.close()

if __name__ == '__main__':
    main()