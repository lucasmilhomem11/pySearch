# 🔍 pySearch

**Enhanced Gobuster-like Tool with Recursive Scanning**

`pySearch` is a powerful Python-based directory and subdomain enumeration tool. It enables penetration testers and bug bounty hunters to efficiently brute-force URLs and domains with support for recursive scanning, custom wordlists, multi-threading, proxies, and more.

---

## 🚀 Features

- 🔄 Recursive scanning of directories and subdomains
- 🧠 Wordlist-based brute-forcing
- ⚡ Multi-threaded performance
- 🎯 Status code filtering
- 🌐 Proxy support
- 📈 Rate limiting
- 📝 Output to file
- 🔧 Verbose logging for debugging

---

## 🧪 Usage

```bash
python pySearch.py [OPTIONS]
```

### Example

```bash
python pySearch.py -d example.com -w wordlist.txt -t 20 -x php,html --recursive -o results.txt --status-filter 200,301
```

---

## 📥 Options

| Option                      | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `-h, --help`               | Show help message and exit                                                  |
| `-u, --url URL`            | Comma-separated list of target URLs (e.g., http://example.com,http://test.com) |
| `-d, --domain DOMAIN`      | Comma-separated list of target domains (e.g., example.com,test.com)         |
| `-w, --wordlist WORDLIST`  | Path to wordlist file                                                       |
| `-t, --threads THREADS`    | Number of concurrent threads                                                |
| `-x, --extensions EXTENSIONS` | File extensions to check (e.g., php,txt,html)                            |
| `-r, --recursive`          | Enable recursive scanning of directories and subdomains                     |
| `-o, --output OUTPUT`      | Output file to save results                                                 |
| `-v, --verbose`            | Enable verbose output                                                       |
| `--proxy PROXY`            | Proxy URL (e.g., http://127.0.0.1:8080)                                     |
| `--rate-limit RATE_LIMIT`  | Limit requests per second (0 for no limit)                                  |
| `--status-filter STATUS_FILTER` | Comma-separated list of status codes to include (e.g., 200,301,302)   |

---

## 🛠 Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/pySearch.git
cd pySearch
```

2. Install dependencies (if any):

```bash
pip install -r requirements.txt
```

---

## 📂 Output

Results are saved to the specified output file in plain text or JSON (if implemented).

---

## 🔐 Disclaimer

This tool is intended for **educational and authorized penetration testing** only. Do **not** use it on targets you do not own or have permission to test.

---

## 🤝 Contributions

Feel free to open issues or PRs to improve the tool! 🚀
