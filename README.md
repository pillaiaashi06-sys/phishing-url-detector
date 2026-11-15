# Phishing URL Detector

A beginner-friendly Python tool that checks a URL for common phishing red flags and gives it a risk score.

## What it checks
- IP address used instead of a domain name
- Too many subdomains
- Suspicious keywords (login, verify, secure, account...)
- Look-alike domains (paypa1.com, g00gle.com)
- '@' symbol in the URL
- Very long URLs and many hyphens
- Missing HTTPS

## How it works
Each red flag adds points to a score:
- 0-2: Looks safe
- 3-4: Suspicious
- 5 or more: Likely phishing

## How to run
1. Install Python 3
2. Download `phishing_detector.py`
3. Run: `python phishing_detector.py`
4. Type a URL when asked. Type `quit` to exit.

## Example
Input: `http://paypa1-secure-login.com/verify`
Output: `Score: 8 -> LIKELY PHISHING`

## Limitations
This is a simple points-based system, so it can give false positives and miss clever attacks. It only uses Python's built-in libraries.

## Disclaimer
For educational purposes only.
