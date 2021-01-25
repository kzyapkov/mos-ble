#!/usr/bin/env python3

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import struct
from dataclasses import dataclass

from bleak import BleakScanner, BleakClient


log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

mos_rpc_uuid = "5f6d4f53-5f52-5043-5f53-56435f49445f"
data_uuid = "5f6d4f53-5f52-5043-5f64-6174615f5f5f"
tx_ctl_uuid = "5f6d4f53-5f52-5043-5f74-785f63746c5f"
rx_ctl_uuid = "5f6d4f53-5f52-5043-5f72-785f63746c5f"


def bda_arg(s):
    if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", s):
        raise argparse.ArgumentTypeError
    return s


def get_argparser():
    parser = argparse.ArgumentParser(description="Mongoose RPC over BLE")
    parser.add_argument("--adapter", type=str, default="hci0")

    subparsers = parser.add_subparsers(dest="cmd")

    parser_scan = subparsers.add_parser("scan", help="Scan for nearby BLE devices")
    parser_scan.add_argument(
        "--timeout", type=int, default=5, help="Scan time, seconds"
    )

    parser_call = subparsers.add_parser("call", help="Invoke a RPC method")
    parser_call.add_argument("method", type=str)
    parser_call.add_argument(
        "-a",
        "--address",
        type=bda_arg,
        default=(os.environ.get("MOS_BLE_ADDR", None)),
        help="BLE device address",
    )
    parser_call.add_argument(
        "-n",
        "--name",
        type=str,
        default=None,
        help="BLE device name",
    )
    parser_call.add_argument(
        "--mgos-args-compat",
        action="store_true",
        help="Use 'args' instead of 'params' for calls, for compatibility with old firmwares",
    )
    parser_call.add_argument("params", type=str, nargs="?", default=None)

    return parser


async def scan():
    devices = await BleakScanner.discover()
    for d in devices:
        print(d)


async def lookup_address(name):
    done = asyncio.Future()

    def _cb(device, adv_data):
        log.debug(f"dev='{device}' adv='{adv_data}'")
        if device.name == name and not done.done():
            done.set_result(device)

    scanner = BleakScanner()
    scanner.register_detection_callback(_cb)
    await scanner.start()
    try:
        device = await asyncio.wait_for(done, 5)
        return device.address
    except asyncio.TimeoutError:
        return None
    finally:
        await scanner.stop()


@dataclass
class RPCCall:
    id: int
    method: str
    params: dict = None
    src: str = "mos-ble"
    dst: str = None
    resolve: asyncio.Future = None
    args_dest = 'params'

    def __init__(self, id: int, method: str, params=None):
        self.id = id
        self.method = method
        self.params = params
        self.resp = bytearray()
        self.resp_len = -1

    @property
    def out_msg(self):
        msg = {
            "id": self.id,
            "method": self.method,
            "src": self.src,
        }
        for o in ("src", "dst"):
            if getattr(self, o) is not None:
                msg[o] = getattr(self, o)
        if self.params is not None:
            msg[self.__class__.args_dest] = self.params
        return msg

    @property
    def request_json(self):
        return json.dumps(self.out_msg)


async def call(address, method, params=None):
    async with BleakClient(address) as client:
        x = await client.is_connected()
        log.debug("Connected: {0}".format(x))

        svcs = await client.get_services()
        if mos_rpc_uuid not in svcs.services:
            log.error(f"{address} doesn't contain the mgos RPC service")
            return

        call = RPCCall(99, method, params)

        req = bytearray(map(ord, call.request_json))
        req_len = bytearray(4)
        struct.pack_into(">I", req_len, 0, len(req))

        await client.write_gatt_char(tx_ctl_uuid, req_len)
        await client.write_gatt_char(data_uuid, req)

        # FIXME:
        # subscribing for notifications on rx_ctl_uuid doesn't work
        # so let's just poll for now
        for _ in range(50):
            res = await client.read_gatt_char(rx_ctl_uuid)
            if len(res) == 4:
                resp_len = struct.unpack(">I", res)[0]
                if resp_len != 0:
                    call.resp_len = resp_len
                    break
            await asyncio.sleep(1)

        if call.resp_len <= 0:
            log.warning("Did not get a response")
            return

        log.debug(f"got {resp_len} bytes to read")
        bytes_left = call.resp_len
        while bytes_left > 0:
            data = await client.read_gatt_char(data_uuid)
            call.resp.extend(data)
            bytes_left -= len(data)

        log.debug(f"resp = {call.resp}")
        try:
            resp = json.loads(call.resp)
        except json.JSONDecodeError as e:
            log.error(f"response not valid JSON: {e}")
            return

        if "error" in resp:
            print(json.dumps(resp["error"], indent=4, sort_keys=True))
            sys.exit(1)
        elif "result" in resp:
            print(json.dumps(resp["result"], indent=4, sort_keys=True))
        else:
            log.error(f"invalid response frame: {resp}")
            sys.exit(2)


def main():
    p = get_argparser()
    args = p.parse_args(sys.argv[1:])

    coro = None
    loop = asyncio.get_event_loop()

    if args.cmd == "scan":
        return loop.run_until_complete(scan())

    if args.cmd == "call":
        if args.mgos_args_compat:
            RPCCall.args_dest = 'args'

        if args.address is None:
            if args.name is None:
                log.error(f"Provide either --name or --address")
                sys.exit(9)

            address = loop.run_until_complete(lookup_address(args.name))
            if address is None:
                log.error(f"Device named {args.name} not found")
                sys.exit(9)

            log.info(f"Found address {address} for {args.name}")
            args.address = address

        if args.params:
            args.params = json.loads(args.params)

        coro = call(args.address, args.method, args.params)
    else:
        log.error(f"unknown command {args.cmd}")

    if coro:
        loop.run_until_complete(coro)


if __name__ == "__main__":
    main()
