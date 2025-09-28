"""
WebSocket service for real-time updates in the Secure Trading Platform
"""
import asyncio
import json
from typing import Dict, List, Optional
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.user_connections: Dict[int, List[WebSocket]] = {}  # user_id -> list of connections

    async def connect(self, websocket: WebSocket, user_id: Optional[int] = None):
        await websocket.accept()
        self.active_connections.append(websocket)
        
        if user_id is not None:
            if user_id not in self.user_connections:
                self.user_connections[user_id] = []
            self.user_connections[user_id].append(websocket)
    
    def disconnect(self, websocket: WebSocket, user_id: Optional[int] = None):
        self.active_connections.remove(websocket)
        
        if user_id is not None and user_id in self.user_connections:
            if websocket in self.user_connections[user_id]:
                self.user_connections[user_id].remove(websocket)
                if not self.user_connections[user_id]:
                    del self.user_connections[user_id]

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)
    
    async def send_to_user(self, user_id: int, message: str):
        if user_id in self.user_connections:
            for connection in self.user_connections[user_id]:
                try:
                    await connection.send_text(message)
                except:
                    # If sending fails, remove the connection
                    self.disconnect(connection, user_id)
    
    async def send_order_update(self, order_data: Dict):
        message = json.dumps({
            "type": "order_update",
            "data": order_data,
            "timestamp": datetime.now().isoformat()
        })
        await self.broadcast(message)
    
    async def send_transaction_update(self, transaction_data: Dict):
        message = json.dumps({
            "type": "transaction_update",
            "data": transaction_data,
            "timestamp": datetime.now().isoformat()
        })
        await self.broadcast(message)
    
    async def send_market_update(self, market_data: Dict):
        message = json.dumps({
            "type": "market_update",
            "data": market_data,
            "timestamp": datetime.now().isoformat()
        })
        await self.broadcast(message)
    
    async def send_security_event(self, event_data: Dict):
        message = json.dumps({
            "type": "security_event",
            "data": event_data,
            "timestamp": datetime.now().isoformat()
        })
        await self.broadcast(message)


# Global connection manager
manager = ConnectionManager()


async def handle_websocket_messages(websocket: WebSocket, user_id: Optional[int] = None):
    """
    Handle incoming messages from WebSocket connections
    """
    await manager.connect(websocket, user_id)
    try:
        while True:
            data = await websocket.receive_text()
            # Process any incoming messages (if needed)
            # For now, we just broadcast received messages
            await manager.broadcast(f"Client says: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)
        await manager.broadcast(f"Client #{user_id} left the chat")