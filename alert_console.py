import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel


class Alert(BaseModel):
    action_alert: str
    action_block: str
    description: str


app = FastAPI()


@app.post("/")
async def show_(alert: Alert):
    print(alert)
    return alert

if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=8000)
