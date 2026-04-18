"""Test DTLS connectivity against GoodWe inverter with WiFi/LAN Kit 2.0."""

import asyncio
import goodwe
import logging
import sys

logging.basicConfig(
    format="%(asctime)-15s %(name)s %(funcName)s(%(lineno)d) - %(levelname)s: %(message)s",
    stream=sys.stderr,
    level=logging.DEBUG,
)

IP_ADDRESS = "192.168.10.7"


async def main():
    print(f"\n=== Step 1: 48899 discovery probe ===", flush=True)
    disc = await goodwe._probe_48899(IP_ADDRESS, timeout=5)
    if disc:
        print(f"Discovery response: {disc}")
    else:
        print("No response on port 48899")
        return

    if not disc.get("dtls"):
        print("Not a DTLS dongle — plain UDP should work")
        return

    print(f"\n=== Step 2: DTLS auto-discover ===", flush=True)
    print("(First request triggers DTLS handshake — may take a few seconds)", flush=True)
    try:
        inverter = await goodwe.discover(IP_ADDRESS)
        print(f"\nSUCCESS!")
        print(f"  Model:    {inverter.model_name}")
        print(f"  Serial:   {inverter.serial_number}")
        print(f"  Firmware: {inverter.firmware}")
    except Exception as e:
        print(f"FAILED discover: {type(e).__name__}: {e}")
        return

    print(f"\n=== Step 3: Read runtime data ===", flush=True)
    try:
        data = await inverter.read_runtime_data()
        print(f"\nSensor readings ({len(data)} values):")
        for sensor in inverter.sensors():
            if sensor.id_ in data:
                print(f"  {sensor.id_:35} {sensor.name} = {data[sensor.id_]} {sensor.unit}")
    except Exception as e:
        print(f"FAILED read_runtime_data: {type(e).__name__}: {e}")


asyncio.run(main())
