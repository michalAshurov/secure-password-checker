import hashlib

def sha1_hex_upper(text):
    data = text.encode("utf-8")
    sha1_hash = hashlib.sha1(data)
    return sha1_hash.hexdigest().upper()

def split_prefix_suffix(sha1_hash: str):
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    return prefix, suffix
