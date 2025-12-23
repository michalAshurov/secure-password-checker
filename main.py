import getpass
import secrets
import string

from hash_utils import sha1_hex_upper, split_prefix_suffix
from hibp_client import fetch_hash_suffixes, parse_range_response, get_pwned_count

SAFE_SYMBOLS = "!@#$%^&*_-+="


def generate_strong_password(length=18):
    if length < 8:
        raise ValueError("Password length must be at least 8")

    upper = secrets.choice(string.ascii_uppercase)
    lower = secrets.choice(string.ascii_lowercase)
    digit = secrets.choice(string.digits)
    symbol = secrets.choice(SAFE_SYMBOLS)

    all_chars = string.ascii_letters + string.digits + SAFE_SYMBOLS
    rest = [secrets.choice(all_chars) for _ in range(length - 4)]

    password_chars = [upper, lower, digit, symbol] + rest
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def check_password_pwned(password):
    sha1 = sha1_hex_upper(password)
    prefix, suffix = split_prefix_suffix(sha1)

    response_text = fetch_hash_suffixes(prefix)
    suffixes_dict = parse_range_response(response_text)

    return get_pwned_count(suffix, suffixes_dict)


def suggest_unpwned_password(max_attempts=15, length=18):
    for _ in range(max_attempts):
        candidate = generate_strong_password(length)
        count = check_password_pwned(candidate)
        if count == 0:
            return candidate
    return None


def main():
    password = getpass.getpass("Enter a password to check (input hidden): ")

    count = check_password_pwned(password)

    if count > 0:
        print(f"This password was found {count} times in data breaches.")
        print("It is strongly recommended to change it.")

        suggestion = suggest_unpwned_password()

        if suggestion:
            print("\nExample of a strong password not found in breaches:")
            print(suggestion)
            print("Use a password manager to store it safely.")
        else:
            print("Could not generate an unpwned password at this time. Please try again.")
    else:
        print("This password was NOT found in known data breaches.")
        print("Still recommended: use a unique password per site.")


if __name__ == "__main__":
    main()
