import http.client
import json

conn = http.client.HTTPSConnection("email-validator-api30.p.rapidapi.com")

payload = json.dumps({
    "email": "user@example.com"  #example email, you can change it to any email you want
})

headers = {
    "x-rapidapi-key": "YOUR_RAPIDAPI_KEY",  #replace with your RapidAPI key
    "x-rapidapi-host": "email-validator-api30.p.rapidapi.com",
    "Content-Type": "application/json"
}

conn.request("POST", "/validate-email", payload, headers)

res = conn.getresponse()
data = res.read()

print(data.decode("utf-8"))
