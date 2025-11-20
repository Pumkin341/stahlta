# Stahlta
A modular Python-based tool designed to detect common and high-impact vulnerabilities in modern web applications.  
The scanner performs both **static and dynamic analysis**, sending crafted payloads and analyzing responses to uncover potential security flaws.

## Key Features
- Detects vulnerabilities such as **SQL Injection**, **Cross-Site Scripting (XSS)**, **CSRF**, insecure cookies, and misconfigured headers  
- Uses **context-aware payload generation** for accurate detection and minimal false positives  
- Generates **comprehensive vulnerability reports** with categorized findings and recommendations  
- Built with a **modular architecture**, making it easy to extend or integrate with other tools  
- Tests for both **traditional** and **modern** attack vectors
- Asynchronous HTTP fetching and processing  
- Single-command CLI invocation  

## Prerequisites

- Python 3.8 or newer  
- `git`  
- [`virtualenv`](https://virtualenv.pypa.io/) or built-in `venv`  

## Installation Guide

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/stahlta.git
cd stahlta
```

### 2. Create & activate a virtual environment

Using the built-in `venv`:

```bash
python3 -m venv .venv
source .venv/bin/activate         # on Bash/Zsh
```

*(If you prefer `virtualenv`, replace `python3 -m venv .venv` with `virtualenv .venv`.)*

### 3. Install in “editable” mode

This will install dependencies and drop a real `stahlta` command into your venv’s `bin/`:

```bash
pip install -e .
```

You should see output like:

```
Obtaining file:///…/stahlta
Installing collected packages: …
  Running setup.py develop for stahlta
Successfully installed stahlta-0.1
```

### 4. Verify installation

```bash
which stahlta
# → /path/to/stahlta/.venv/bin/stahlta
```

### 5. Run the CLI

You can now run `stahlta` from **any** directory:

```bash
stahlta -u https://example.com/api/data 
```

Refer to `stahlta --help` for a full list of options.

---
