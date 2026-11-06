import sys, re, pathlib, secrets
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# C. TOKEN ISOLATION: real token stays inside the vault; agent only gets a handle
class TokenVault:
    def __init__(self, real_token: str, trusted_hosts: set):
        self.__token = real_token
        self.__trusted = trusted_hosts
        self.handle = "vault-ref-" + secrets.token_hex(4)

    def authorized_request(self, url: str):
        host = urlparse(url).hostname
        if host not in self.__trusted:
            raise PermissionError(f"Vault refused: {host} is not a trusted host")
        return requests.get(url, headers={"Authorization": f"Bearer {self.__token}"}, timeout=5)

    def __repr__(self):
        return f"<TokenVault handle={self.handle} token=REDACTED>"

VAULT = TokenVault("abc123xyz", trusted_hosts={"bank.example"})

# A. INPUT SANITIZATION: only known-safe meta fields survive
ALLOWED_META = {"description", "viewport", "keywords", "author", "robots"}

def sanitize(doc: str) -> BeautifulSoup:
    soup = BeautifulSoup(doc, "html.parser")
    for meta in soup.find_all("meta"):
        name = (meta.get("name") or "").lower()
        if name and name not in ALLOWED_META:
            print(f"[A] Sanitizer: stripped unknown meta field '{name}' "
                  f"(content={meta.get('content')!r})")
            meta.decompose()
    return soup

# B. CAPABILITY RESTRICTION: tiny command set, and only from the user
ALLOWED_COMMANDS = {"click", "scroll"}

def execute(command: str, source: str):
    if source != "user":
        print(f"[B] Blocked: '{command}' came from {source}, not the user")
        return
    verb = command.split()[0].lower() if command.split() else ""
    if verb not in ALLOWED_COMMANDS:
        print(f"[B] Blocked: '{verb.upper()}' is not in allowed set {sorted(ALLOWED_COMMANDS)}")
        return
    print(f"[B] Executed allowed command: {command}")

def load_page(path_or_url: str) -> str:
    p = pathlib.Path(path_or_url)
    if p.exists():
        return p.read_text()
    return requests.get(path_or_url, timeout=5).text

def run_agent(raw_doc: str):
    print("=== A. Input Sanitization ===")
    soup = sanitize(raw_doc)
    meta = soup.find("meta", attrs={"name": "ai-instructions"})
    print("[A] ai-instructions visible to agent after sanitizing:", bool(meta))

    print("\n=== B. Capability Restriction ===")
    injected = re.search(r'name="ai-instructions"\s+content="([^"]+)"', raw_doc)
    if injected:
        execute(injected.group(1), source="page content")
    execute("POST http://127.0.0.1:8088/collect", source="user")
    execute("scroll down", source="user")
    execute("click #login", source="user")

    print("\n=== C. Token Isolation ===")
    print("[C] What the agent can see:", VAULT)
    print("[C] If exfiltrated, attacker would receive:", VAULT.handle, "(not the real token)")
    try:
        VAULT.authorized_request("http://127.0.0.1:8088/collect")
    except PermissionError as e:
        print("[C]", e)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python agent_browser_hardened.py <file-or-url>")
        sys.exit(1)
    run_agent(load_page(sys.argv[1]))