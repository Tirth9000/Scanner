import time, requests


url = "http://localhost:8000/webhook"

count = 0

data = {
    "event_count" : count,
    "event": "test_event",
    "data": {
        "message": "hello from webhook client"
    }
}

    
for count in range(5):
   print(f"Sending webhook {count}") 
   response = requests.post(url, json=data)
   print("Response:", response.json())
   count += 1
   time.sleep(2)
