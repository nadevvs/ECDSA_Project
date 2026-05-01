import hashlib


def hash_message(message: str) -> int:
    message_bytes = message.encode("utf-8")
    digest = hashlib.sha256(message_bytes).digest()
    return int.from_bytes(digest, byteorder="big")
