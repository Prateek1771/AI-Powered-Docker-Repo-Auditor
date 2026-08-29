import asyncio
import json
import sys

import websockets

from app.dev.keys import mint_token


async def main() -> None:
    job_id = sys.argv[1]

    port = sys.argv[2] if len(sys.argv) > 2 else "8080"

    token = mint_token("demo-tenant")

    url = f"ws://localhost:{port}/ws/jobs/{job_id}?token={token}"

    async with websockets.connect(url) as ws:
        async for raw in ws:
            event = json.loads(raw)

            if event.get("type") == "ping":
                continue

            bar = "#" * (event["progress"] // 5)

            print(f"{event['progress']:3d}% |{bar:<20}| {event['step']}")

            if event["status"] in ("completed", "failed"):
                break


if __name__ == "__main__":
    asyncio.run(main())
