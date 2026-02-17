from fastapi import FastAPI, Request


app = FastAPI()


@app.post("/webhook")
def webhook(request: dict):
    print("Received webhook:", request)

    
    return {"status": "success"}


if __name__ == "__main__":
    import uvicorn 

    uvicorn.run(app, host="0.0.0.0", port=8000)