# Stahlta


## Features

- Asynchronous HTTP fetching and processing  
- Plugin‐style `components/` architecture  
- Single-command CLI invocation  

## Prerequisites

- Python 3.8 or newer  
- `git`  
- (Optional) [`virtualenv`](https://virtualenv.pypa.io/) or built-in `venv`  

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
