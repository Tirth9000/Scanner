from fastapi import FastAPI
import uuid, redis, json

app = FastAPI()

rdb = redis.Redis(host='localhost', port=6379, db=0)

@app.get("/")
async def read_root():
    return {"message": "Scanner API is running."}


@app.post("/scan")
async def start_scan(request: dict):
    scan_id = str(uuid.uuid4())

    domain = request.get("domain")
    print(domain)

    job = {
        "scan_id": str(scan_id),
        "domain": domain,
        "status": "started",
        "details": "Scan has been initiated."
    }    

    rdb.lpush("scan_jobs", json.dumps(job))

    return {"scan_id": scan_id, "message": "Scan started successfully."}


@app.get("/clear")
def clear_scan_queue():
    queue_name = "scan_jobs"

    removed_items = rdb.llen(queue_name)

    rdb.delete(queue_name)

    return {
        "queue": queue_name,
        "cleared": True,
        "removed_items": removed_items
    }



if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="localhost", port=8000)