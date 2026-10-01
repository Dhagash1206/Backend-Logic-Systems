import requests

BASE_URL = "http://localhost:8000"
TOKEN = "YOUR_TOKEN"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
TIMEOUT = 10

try:
    response = requests.post(
        f"{BASE_URL}/users",
        json={"name": "Asha", "email": "asha@example.com"},
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    created_user = response.json()
    print("Created:", created_user)

    response = requests.get(
        f"{BASE_URL}/users/{created_user['id']}",
        headers=HEADERS,
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    print("Fetched:", response.json())

    response = requests.get(f"{BASE_URL}/users", headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    print("All:", response.json())

except requests.exceptions.Timeout:
    print("Request timed out")
except requests.exceptions.HTTPError as e:
    print("HTTP error:", e.response.status_code, e.response.text)
except requests.exceptions.RequestException as e:
    print("Request failed:", e)