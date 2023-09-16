import csv

with open("credentials.csv") as creds:
    reader = csv.reader(creds)
    for i in reader:
        username, password = i
        print(username)