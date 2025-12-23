import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"


def fetch_hash_suffixes(prefix):
    url = HIBP_RANGE_URL.format(prefix)

    headers = {
        "User-Agent": "password-k-anonymity-learning-project",
        "Add-Padding": "true"
    }

    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()

    return response.text


def parse_range_response(response_text):
    suffixes = {}

    for line in response_text.splitlines():
        suffix, count = line.split(":")
        suffixes[suffix] = int(count)

    return suffixes

def get_pwned_count(suffix: str, suffixes_dict: dict[str, int]) -> int:
    return suffixes_dict.get(suffix, 0)