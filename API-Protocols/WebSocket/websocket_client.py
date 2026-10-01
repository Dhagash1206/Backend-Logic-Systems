import asyncio
import websockets

TOKEN = "YOUR_TOKEN"
URL = "ws://localhost:8765"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


async def main():
    try:
        async with websockets.connect(
            URL,
            additional_headers=HEADERS,
            open_timeout=5,
            ping_timeout=10,
        ) as websocket:
            await websocket.send("hello from client")
            message = await asyncio.wait_for(websocket.recv(), timeout=30)
            print("Received:", message)

    except asyncio.TimeoutError:
        print("Timed out waiting for a message")
    except websockets.exceptions.InvalidStatus as e:
        print("Connection rejected:", e.response.status_code)
    except websockets.exceptions.ConnectionClosed as e:
        print("Connection closed:", e.code, e.reason)
    except OSError as e:
        print("Could not connect:", e)


asyncio.run(main())