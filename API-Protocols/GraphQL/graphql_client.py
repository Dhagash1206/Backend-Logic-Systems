import requests

url = "http://localhost:8002/graphql"
query_text = "{ books { title author } }"
headers = {"Authorization": "Bearer YOUR_TOKEN"}

try:
    response = requests.post(
        url,
        json={"query": query_text},
        headers=headers,
        timeout=10,
    )
    response.raise_for_status()
    result = response.json()

    if "errors" in result:
        print("GraphQL errors:", result["errors"])
    else:
        print(result["data"])

except requests.exceptions.Timeout:
    print("Request timed out")
except requests.exceptions.RequestException as e:
    print("Request failed:", e)