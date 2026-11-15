# Phishing URL Detector

A beginner-friendly Python tool that checks a URL for common phishing red flags and gives it a risk score.
## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Spyder](https://img.shields.io/badge/Spyder_IDE-FF0000?style=for-the-badge&logo=spyder&logoColor=white)
![Git](https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white)
![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-D32F2F?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Beginner_Project-2EA44F?style=for-the-badge)

### 📚 Python libraries used (all built in, nothing to install)
![urllib](https://img.shields.io/badge/urllib.parse-3776AB?style=flat-square&logo=python&logoColor=white)
![ipaddress](https://img.shields.io/badge/ipaddress-FFD43B?style=flat-square&logo=python&logoColor=black)
![difflib](https://img.shields.io/badge/difflib-8A2BE2?style=flat-square&logo=python&logoColor=white)

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
