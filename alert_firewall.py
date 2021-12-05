import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel


class Rule(BaseModel):
    rule: str
    value: str


app = FastAPI()


@app.post("/")
async def show_(rule: Rule):
    print(rule)
    return rule

if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=8001)
