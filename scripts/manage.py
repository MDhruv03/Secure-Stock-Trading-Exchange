# scripts/manage.py

import asyncio
import uvicorn
import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.database import database, metadata, engine
from app.models import users, orders, trades, merkle_roots, ids_alerts, incidents, blocklist
from app.security import get_password_hash
from app.utils.demo_data import seed_demo_data

async def init_db():
    print("Initializing database...")
    async with database.connection():
        metadata.create_all(engine)
    print("Database initialized.")

async def seed_db():
    await seed_demo_data()

async def start_app():
    print("Starting FastAPI application...")
    config = uvicorn.Config("app.main:app", host="0.0.0.0", port=8000, reload=True)
    server = uvicorn.Server(config)
    await server.serve()

async def main():
    if len(sys.argv) < 2:
        print("Usage: python manage.py <command>")
        print("Commands: init_db, seed_db, start_app")
        return

    command = sys.argv[1]

    if command == "init_db":
        await init_db()
    elif command == "seed_db":
        await seed_db()
    elif command == "start_app":
        await start_app()
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    import sys
    asyncio.run(main())
