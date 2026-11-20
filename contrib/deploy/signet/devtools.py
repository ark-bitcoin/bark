#!/usr/bin/env python3
"""Public test helpers for the private signet, served at https://<host>/dev/.

The signet coins have no value, but the miner and the faucet are shared, so
every endpoint has a cap and there is a global rate limit.

  POST /dev/faucet        {"address": "tb1...", "btc": 0.01}   max 0.1 BTC
  POST /dev/mine          {"blocks": 1}                        max 6 blocks
  POST /dev/store-wallet  {"name": "My Store"}
      creates a watch-only stand-in for the host app's on-chain account and
      returns its public descriptor, for a store registration.
  GET  /dev/              this text

Mining is limited because signet retargets like mainnet: many quick blocks
raise the difficulty for everyone.
"""

import json
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATADIR = "/var/lib/scuttle/bitcoind"
MINER = "/opt/scuttle/bin/signet-mine"
LISTEN = ("127.0.0.1", 3090)

MAX_FAUCET_BTC = 0.1
MAX_BLOCKS = 6
# A sliding window per endpoint: (max calls, seconds).
LIMITS = {"faucet": (30, 600), "mine": (20, 600), "store-wallet": (20, 600)}

_calls: dict[str, list[float]] = {}
_lock = threading.Lock()


def allowed(endpoint: str) -> bool:
	limit, window = LIMITS[endpoint]
	now = time.time()
	with _lock:
		calls = [t for t in _calls.get(endpoint, []) if now - t < window]
		if len(calls) >= limit:
			_calls[endpoint] = calls
			return False
		calls.append(now)
		_calls[endpoint] = calls
		return True


def cli(*args: str) -> str:
	out = subprocess.run(
		["bitcoin-cli", f"-datadir={DATADIR}", "-signet", *args],
		capture_output=True, text=True, timeout=120,
	)
	if out.returncode != 0:
		raise RuntimeError(out.stderr.strip() or "bitcoin-cli failed")
	return out.stdout.strip()


def mine(blocks: int) -> int:
	out = subprocess.run([MINER, str(blocks)], capture_output=True, text=True, timeout=300)
	if out.returncode != 0:
		raise RuntimeError(out.stderr.strip() or "mining failed")
	return int(out.stdout.strip().splitlines()[-1])


def faucet(body: dict) -> dict:
	address = str(body.get("address", ""))
	btc = float(body.get("btc", 0.01))
	if not 0 < btc <= MAX_FAUCET_BTC:
		raise ValueError(f"btc must be between 0 and {MAX_FAUCET_BTC}")
	if not json.loads(cli("validateaddress", address)).get("isvalid"):
		raise ValueError("not a valid signet address")
	txid = cli("-rpcwallet=miner", "sendtoaddress", address, f"{btc:.8f}")
	# Confirm it, so the coins can be boarded right away.
	height = mine(1)
	return {"txid": txid, "btc": btc, "height": height}


def store_wallet(body: dict) -> dict:
	name = str(body.get("name", "")).strip()
	slug = re.sub(r"[^a-z0-9]", "", name.lower())[:40]
	if not slug:
		raise ValueError("name must contain letters or digits")
	wallet = f"store-{slug}"
	try:
		cli("-named", "createwallet", f"wallet_name={wallet}")
	except RuntimeError as e:
		if "already exists" not in str(e):
			cli("loadwallet", wallet)
	descs = json.loads(cli(f"-rpcwallet={wallet}", "listdescriptors"))["descriptors"]
	desc = next(d["desc"] for d in descs if d["desc"].startswith("tr(") and not d["internal"])
	return {"wallet": wallet, "onchain_descriptor": desc}


class Handler(BaseHTTPRequestHandler):
	def reply(self, status: int, body) -> None:
		data = (body if isinstance(body, str) else json.dumps(body)).encode()
		self.send_response(status)
		self.send_header("Content-Type", "text/plain" if isinstance(body, str) else "application/json")
		self.send_header("Content-Length", str(len(data)))
		self.end_headers()
		self.wfile.write(data)

	def endpoint(self) -> str:
		# Tailscale strips the /dev mount; accept both forms.
		path = self.path.split("?")[0].rstrip("/")
		return path.removeprefix("/dev").lstrip("/")

	def do_GET(self) -> None:
		self.reply(200, __doc__)

	def do_POST(self) -> None:
		endpoint = self.endpoint()
		handlers = {"faucet": faucet, "mine": lambda b: {"height": mine(min(max(int(b.get("blocks", 1)), 1), MAX_BLOCKS))},
			"store-wallet": store_wallet}
		if endpoint not in handlers:
			return self.reply(404, {"error": "no such endpoint"})
		if not allowed(endpoint):
			return self.reply(429, {"error": "rate limited, try again in a few minutes"})
		try:
			length = int(self.headers.get("Content-Length") or 0)
			body = json.loads(self.rfile.read(length) or b"{}")
			self.reply(200, handlers[endpoint](body))
		except (ValueError, TypeError, KeyError) as e:
			self.reply(400, {"error": str(e)})
		except Exception as e:  # noqa: BLE001 - report bitcoind errors to the caller
			self.reply(502, {"error": str(e)})

	def log_message(self, fmt: str, *args) -> None:
		print(f"{self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
	ThreadingHTTPServer(LISTEN, Handler).serve_forever()
