# ssrf-probe

An authorized **SSRF (Server-Side Request Forgery) testing toolkit**: it generates
a curated set of SSRF probe payloads, injects them into a target request, and tells
you which ones are worth verifying — using response analysis and, for blind SSRF, an
out-of-band (OAST) callback listener.

> ⚠️ **Authorized use only.** This tool sends crafted requests that try to make a
> server reach unintended destinations. Run it **only** against systems you own or
> have explicit written permission to test. The CLI refuses to run without the
> `--authorized` flag.

## Why

Server-side URL fetchers (webhooks, link previews, PDF/image renderers, import-by-URL
features) are a common SSRF sink. Confirming the bug by hand is repetitive: you try
loopback, the alternate IP encodings that slip past naive `is it 127.0.0.1?` checks,
cloud metadata endpoints, non-HTTP schemes, and — when the response is blank — a blind
callback. `ssrf-probe` packages that checklist so you can point it at an authorized
target and get a short list to verify, instead of doing it one `curl` at a time.

## What it covers

| Category | Examples |
| --- | --- |
| Loopback / encodings | `127.0.0.1`, `localhost`, `2130706433`, `0x7f.0x0.0x0.0x1`, `0177.0.0.1`, `[::1]`, `[::ffff:127.0.0.1]` |
| Cloud metadata | AWS/OpenStack `169.254.169.254`, GCP `metadata.google.internal`, Azure IMDS, Alibaba `100.100.100.200` |
| Alternate schemes | `file://`, `dict://`, `gopher://` |
| Blind (out-of-band) | `http://<token>.<your-oob-domain>/` confirmed by the built-in listener |

Each cloud-metadata payload carries **response markers** (stable strings those
endpoints return), so a reflected response is flagged `likely` automatically. A blind
probe is only reported `confirmed` when your listener actually receives the callback.

## Install

```bash
git clone https://github.com/Secx1/ssrf-probe
cd ssrf-probe
pip install -e .
```

Pure standard library — no third-party runtime dependencies.

## Usage

Reflected / direct SSRF against a lab target you control:

```bash
ssrf-probe --template 'http://target.local/fetch?url=FUZZ' --authorized
```

`FUZZ` marks where the target fetches a URL. Payloads are URL-encoded into that spot.

Blind SSRF with the out-of-band listener (run on a host the target can reach):

```bash
ssrf-probe \
  --template 'http://target.local/webhook?callback=FUZZ' \
  --authorized \
  --oob-domain oast.example.com \
  --listen 0.0.0.0:8080
```

Point the DNS for `*.oast.example.com` at the machine running the listener; each blind
probe embeds a unique token so a hit is attributed to the exact payload.

### Output

```
   [inconclusive] loopback http://127.0.0.1/ HTTP 200
>> [likely] cloud-metadata http://169.254.169.254/latest/meta-data/ HTTP 200 markers=ami-id,instance-id
>> [confirmed] oob http://<token>.oast.example.com/ OOB-HIT
```

`>>` lines (`likely` / `confirmed`) are the ones to verify by hand.

## Library use

```python
from ssrf_probe import Engine, all_payloads

engine = Engine()
for r in engine.run("http://target.local/fetch?url=FUZZ", all_payloads()):
    if r.confidence in {"likely", "confirmed"}:
        print(r.summary())
```

The `Engine` takes an injectable `fetcher`, so you can plug in your own HTTP client
(auth headers, proxies) or run it fully offline in tests.

## Development

```bash
pip install pytest
pytest -q
```

## Responsible use

This is defensive/assessment tooling. Findings are meant to be reported to the system
owner so the SSRF sink can be fixed (allow-list destinations, block link-local and
metadata ranges, disable unused URL schemes). Do not run it against infrastructure you
are not authorized to test.

## License

MIT — see [LICENSE](./LICENSE).
