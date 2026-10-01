import asyncio
import os
import websockets
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Response
from websockets.datastructures import Headers

API_TOKEN = os.getenv("API_TOKEN", "YOUR_TOKEN")
MAX_MESSAGE_BYTES = 1024 * 1024
connected_clients: set = set()


async def authenticate(connection, request):
    if request.headers.get("Authorization") != f"Bearer {API_TOKEN}":
        return Response(401, "Unauthorized", Headers(), b"Unauthorized\n")
    return None


async def send_safely(client, message):
    try:
        await client.send(message)
    except ConnectionClosed:
        connected_clients.discard(client)


async def handle_client(websocket):
    connected_clients.add(websocket)
    try:
        async for incoming_message in websocket:
            if not incoming_message.strip():
                await websocket.send("error: empty message")
                continue
            await asyncio.gather(
                *(
                    send_safely(client, incoming_message)
                    for client in list(connected_clients)
                    if client is not websocket
                )
            )
    except ConnectionClosed:
        pass
    finally:
        connected_clients.discard(websocket)


async def main():
    async with websockets.serve(
        handle_client,
        "localhost",
        8765,
        process_request=authenticate,
        open_timeout=5,
        ping_interval=20,
        ping_timeout=10,
        close_timeout=5,
        max_size=MAX_MESSAGE_BYTES,
    ):
        print("WebSocket server on ws://localhost:8765")
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server stopped")