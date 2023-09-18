from ecdsa import SigningKey
import hashlib
import random
import ecdsa


class SignerEngine:
    def __init__(self, password: str):
        self.password = password
        self._private_key = self.generate_key_from_password()
        self._public_key = self._private_key.get_verifying_key()

    def verify_sign(self, sign, data, signature) -> bool:
        return sign.verify(signature, data, hashfunc=hashlib.sha256)

    def sign(self, data: bytes or str):
        if type(data) is str:
            data.encode("utf-8")

        return self._private_key.sign(data, hashfunc=hashlib.sha256)

    @property
    def private_key(self) -> str:
        return self._private_key.to_string("compressed").hex()

    @private_key.setter
    def private_key(self, value: str) -> None:
        raise ValueError

    @property
    def public_key(self) -> str:
        return self._public_key.to_string("compressed").hex()

    @public_key.setter
    def public_key(self, value: str) -> None:
        raise ValueError

    def get_public_key(self):
        return self._public_key

    def generate_key_from_password(self):
        private_key_hex = ""
        hexes = ["1", "2", "3", "4", "5", "6", "7",
                 "8", "9", "a", "b", "c", "d", "e", "f"]

        seed = "".join([str(ord(i)) for i in self.password])

        random.seed(seed)
        for _ in range(0, 64):
            private_key_hex += hexes[random.randint(0, 14)]

        private_key_bytes = bytes.fromhex(private_key_hex)
        return SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
