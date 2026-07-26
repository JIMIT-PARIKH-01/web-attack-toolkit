# Web Attack Toolkit

[![CI](https://github.com/JIMIT-PARIKH-01/web-attack-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/JIMIT-PARIKH-01/web-attack-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

Web-application testing tools — **dependency-free**, GUI + CLI.

1. **Content brute-forcer** — probes a wordlist of paths, reports non-404 hits
2. **Tech fingerprinter** — infers stack (CMS/framework/libs) from headers, cookies, body
3. **SQLi tester** — error-based SQL-injection detection on `?param=` values
4. **XSS scanner** — reflected-XSS detection (unencoded marker reflection)

Standard library only (`urllib`, `concurrent.futures`). Python 3.8+.

## ⚠️ AUTHORIZED TARGETS ONLY
Content discovery, SQLi and XSS testing against systems you don't own or lack
written permission to test **may be illegal**. Use on your own labs, deliberately
vulnerable apps (DVWA, WebGoat, juice-shop), CTFs, or sanctioned engagements.

## Run
```powershell
python webattack/gui.py         # GUI, or run.bat

python -m webattack dirs   https://target
python -m webattack finger https://target
python -m webattack sqli   "https://target/item?id=1"
python -m webattack xss    "https://target/search?q=test"
```

## Layout
```
web-attack-toolkit/
└── webattack/
    ├── dirbrute.py     # content discovery
    ├── fingerprint.py  # tech-stack detection
    ├── sqli.py         # error-based SQLi
    ├── xss.py          # reflected XSS
    ├── cli.py  gui.py  run.bat
```

MIT — see [LICENSE](./LICENSE).

## ⬇️ Download & Install

**This is a public tool — download and use it on your device for free.**

```bash
# 1) Clone it
git clone https://github.com/JIMIT-PARIKH-01/web-attack-toolkit.git
cd web-attack-toolkit

# 2) ...or download a ZIP (no git needed)
#    https://github.com/JIMIT-PARIKH-01/web-attack-toolkit/archive/refs/heads/main.zip

# 3) ...or install the command straight from GitHub
pip install git+https://github.com/JIMIT-PARIKH-01/web-attack-toolkit.git
```

Then run it as shown in the usage section above (CLI `python -m ...`, or launch
the GUI via `run.bat`).

<details>
<summary><b>🔒 Requesting access to a private tool</b></summary>

Public tools install with the commands above. If a tool is **private**, access
is granted by the owner through GitHub — a static link cannot unlock private
code, only GitHub can:

1. **Request access** — open an [access request](https://github.com/JIMIT-PARIKH-01/JIMIT-PARIKH-01/issues/new?template=tool-access-request.md&title=Access+request:+web-attack-toolkit) or message on
   [LinkedIn](https://www.linkedin.com/in/jimit-devangkumar-parikh/).
2. The owner reviews it and, if approved, **adds you as a collaborator** on the
   private repository.
3. GitHub then lets you clone / download it with your own account. Access is
   revoked the moment the owner removes you as a collaborator.

</details>

