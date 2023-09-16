import hashlib

password = "palle"

print(type(hashlib.sha256(password.encode('utf8')).hexdigest()))