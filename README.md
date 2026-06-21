# Web Directory Buster

**Multi-threaded vulnerability scanner for enumerating hidden paths on web servers.**  
Built for security assessments, CTF challenges, and penetration testing. Filters out `404 Not Found` clutter to focus on actionable status codes (`200`, `301`, `302`, `403`, `500`, etc.).

---

## 🚀 Technical Overview

- **Concurrency**: Thread-pool model using Python’s `threading` and `queue` libraries for rapid directory traversal.
- **HTTP Engine**: `requests` session with custom `User-Agent`, timeout controls, and SSL error handling.
- **Status-Code Filtering**: Ignores `404` by default; displays all other HTTP statuses, including redirects with optional `Location` header.
- **Robust Error Handling**: Gracefully manages timeouts, connection resets, invalid URLs, and SSL certificate issues.
- **CLI Interface**: Lightweight argument parser supporting wordlist files or inline comma-separated path lists.

---

## 📋 Prerequisites

- **Python 3.6+**
- `requests` library (installed via pip)

---

## ⚙️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/web-directory-buster.git
   cd web-directory-buster
