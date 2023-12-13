import sqlite3
from fastapi import FastAPI

app = FastAPI()


@app.get("/ips")
async def read_ips():
    conection = sqlite3.connect('attackers_ips.db')
    cursor = conection.cursor()
    cursor.execute("SELECT * FROM attackers")

    ips = cursor.fetchall()
    ips_return = dict(ips)

    return {"IPS": ips_return}


@app.get("/ips/{ip}")
async def read_ip(ip: str):
    conection = sqlite3.connect('attackers_ips.db')
    cursor = conection.cursor()
    cursor.execute("SELECT * FROM attackers WHERE ip = ?", (ip,))
    ip = cursor.fetchall()

    ip_return = dict(ip)
    key = list(ip_return.keys())
    value = list(ip_return.values())

    return {"IP": key[0], "Ports": value[0]}
