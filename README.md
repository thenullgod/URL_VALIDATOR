# Phishing URL Detector

`url_detector.py` is a small CLI helper that validates a single URL both syntactically and by probing it on the network before you run any deeper phishing analysis.

## Requirements

- Python 3.11+ (3.14 tested)
- [`requests`](https://pypi.org/project/requests/) (pulls in `urllib3`, `certifi`, and `charset_normalizer`)

Install the dependency with:

```bash
python3 -m pip install --user requests
```

You may want to add `~/Library/Python/<version>/bin` to your `PATH` if pip warns about scripts being installed out of `PATH`.

## Usage

```bash
python3 "phishing url detector/url_detector.py" https://example.com
```

- The tool insists on `http://` or `https://` URLs.
- It sends a HEAD request (with GET fallback) to confirm reachability.
- Outputs `VALID` with notes (e.g., `TLS verified`, `HSTS enabled`, `insecure scheme (HTTP)`), or `INVALID` with the error reason.
- Exit code `0` indicates success; `1` indicates a syntax error, network error, or server error (HTTP ≥ 400).

Use this helper in automation or as a pre-check before feeding URLs into more advanced phishing detection workflows.
