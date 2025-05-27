#!/usr/bin/env python3

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, TaskID
import requests
from bs4 import BeautifulSoup
import re
import jsbeautifier # For beautifying JS to make regex more reliable
from urllib.parse import urljoin, urlparse, unquote

# --- Configuration ---
APP_NAME = "Web Recon Tool"
VERSION = "0.2.1" # Incremented for secret detection improvements

# --- Regular Expressions ---
URL_REGEX = r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))"""

# Regex to detect common placeholder patterns for API keys/secrets
PLACEHOLDER_REGEX = re.compile(
    r"^(?:YOUR|ENTER|INSERT|REPLACE|MY|CHANGE)?(?:[-_ ](?:API|ACCESS|SECRET|PUBLIC|PRIVATE))?[-_ ](?:KEY|TOKEN|SECRET|PASSWORD|PWD|AUTH)(?:[-_ ]HERE)?(?:[\s:=]*<[^>]+>)?(?:[\s:=]*\[[^\]]+\])?Z$",
    re.IGNORECASE
)
# Common words that, if found as a password value, likely indicate a false positive or weak/example password
COMMON_WORDS_FOR_PASSWORD_FP_CHECK = {"password", "example", "test", "admin", "root", "default", "secret", "token", "key", "changeme", "placeholder", "password123", "123456"}


SECRET_PATTERNS = {
    "API Key (Generic AlphaNum)": {
        "pattern": r"""(['"]?(?:api_?key|api_?token|access_?key|secret_?key|auth_?token|client_?secret|api_?secret|private_?key)['"]?\s*[:=]\s*['"]?\s*([a-zA-Z0-9\-_./+=]{20,128})\s*['"]?)""",
        "value_group": 2,
        "desc": "Generic API key/token with alphanumeric and common special characters."
    },
    "API Key (Hexadecimal)": {
        "pattern": r"""(['"]?(?:hex_?key|encryption_?key|app_?key|service_?key)['"]?\s*[:=]\s*['"]?\s*([a-fA-F0-9]{32,128})\s*['"]?)""",
        "value_group": 2,
        "desc": "Hexadecimal-based key (e.g., for encryption, app identifiers)."
    },
    "Authorization Bearer Token": {
        "pattern": r"""(['"]Authorization['"]\s*:\s*['"]Bearer\s+([a-zA-Z0-9\-_.~+/]+=*)['"])""",
        "value_group": 2,
        "desc": "Bearer token in an Authorization header."
    },
    "JSON Web Token (JWT)": {
        "pattern": r"""eyJ[A-Za-z0-9\-_=]{10,}\.eyJ[A-Za-z0-9\-_=]{10,}\.(?:[A-Za-z0-9\-_.+/=]{10,}|$)""", # Min length for segments
        "value_group": 0,
        "desc": "JSON Web Token, commonly used for authentication."
    },
    "AWS Access Key ID": {
        "pattern": r"""(A[SK]IA[0-9A-Z]{16})""",
        "value_group": 1,
        "desc": "Amazon Web Services Access Key ID."
    },
    "AWS Secret Access Key": {
        "pattern": r"""(?<![a-zA-Z0-9/+=])([a-zA-Z0-9/+=]{40})(?![a-zA-Z0-9/+=])""",
        "value_group": 1,
        "desc": "Amazon Web Services Secret Access Key."
    },
    "Google API Key (AIza)": {
        "pattern": r"""(AIza[0-9A-Za-z\-_]{35})""",
        "value_group": 1,
        "desc": "Google API Key."
    },
     "Google OAuth Access Token": {
        "pattern": r"""ya29\.[0-9A-Za-z\-_]{40,150}""", # Common prefix for Google OAuth tokens
        "value_group": 0,
        "desc": "Google OAuth Access Token."
    },
    "GitHub Token": {
        "pattern": r"""(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})""",
        "value_group": 1,
        "desc": "GitHub Personal Access Token."
    },
    "Slack Token": {
        "pattern": r"""(xox[pbarso]-[0-9a-zA-Z]{10,48})""",
        "value_group": 1,
        "desc": "Slack API Token (bot, user, app)."
    },
    "Stripe API Key": {
        "pattern": r"""((?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,99})""",
        "value_group": 1,
        "desc": "Stripe API Key (secret or publishable)."
    },
    "Private Key (BEGIN Marker)": {
        "pattern": r"""-----BEGIN ((?:RSA|OPENSSH|DSA|EC|PGP|ENCRYPTED)\s+)?PRIVATE KEY-----""",
        "value_group": 0,
        "desc": "Start marker for a PEM encoded private key."
    },
    "Password (High Confidence Variable Assignment)": {
        "pattern": r"""(['"]?(?:password|passwd|pwd|pass|secret_phrase|admin_pass|user_pass|private_key_password)['"]?\s*[:=]\s*['"]\s*([^\s'"`;]{10,128})\s*['"])""", # Min length 10
        "value_group": 2,
        "desc": "Password-like string assigned to a common password variable name."
    },
    "Connection String (Common DBs/Services)": {
        "pattern": r"""(['"]?(?:connection_?string|db_?url|database_?url|redis_?url|amqp_?url|mqtt_?url)['"]?\s*[:=]\s*['"]?(mongodb(?:srv)?:\/\/[^\s'"]+|postgres(?:ql)?:\/\/[^\s'"]+|mysql:\/\/[^\s'"]+|redis:\/\/[^\s'"]+|amqp[s]?:\/\/[^\s'"]+|mqtt[s]?:\/\/[^\s'"]+|mssql:\/\/[^\s'"]+)['"]?)""",
        "value_group": 2, # The actual URL part
        "desc": "Database or service connection string."
    },
    "Firebase URL/Project ID": {
        "pattern": r"""https://[a-zA-Z0-9\-_]+\.firebaseio\.com""",
        "value_group": 0,
        "desc": "Firebase database URL."
    },
     "SSH Key (id_rsa, id_dsa etc.)": {
        "pattern": r"""id_(?:rsa|dsa|ed25519|ecdsa)(?:_?(?:pub|key))?""", # Matches common private/public key filenames
        "value_group": 0,
        "desc": "Common SSH key filename pattern (often found in paths)."
    },
}


API_PATH_PATTERNS_REGEX = re.compile(
    r"""
    (?:/api(?:[/\?#]|$))|
    (?:/v[1-9]\d*(?:[/\?#]|$))|
    (?:/rest(?:[/\?#]|$))|
    (?:/rpc(?:[/\?#]|$))|
    (?:/graphql(?:[/\?#]|$))|
    (?:/wp-json(?:[/\?#]|$))|
    (?:/_api(?:[/\?#]|$))|
    (?:/service[s]?(?:[/\?#]|$))|
    (?:\.json(?:[/\?#]|$))|
    (?:\.xml(?:[/\?#]|$))|
    (?:/_{0,1}functions(?:[/\?#]|$))|
    (?:/execute-api(?:[/\?#]|$))|
    (?:/api-docs(?:[/\?#]|$))|
    (?:/swagger(?:[/\?#]|$))|
    (?:/openapi(?:[/\?#]|$))|
    (?:/_{0,1}trpc(?:[/\?#]|$))
    """,
    re.VERBOSE | re.IGNORECASE
)

JS_API_CALL_PATTERNS_REGEX = {
    "Fetch/Axios/XHR String Literal": re.compile(r"""(?:fetch|axios\s*\.\s*(?:get|post|put|delete|patch|head|options|request)|new\s+XMLHttpRequest\s*\(\s*\)\s*\.\s*open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]\s*,\s*)['"]((?:[^'"\\]|\\.)+)['"]"""),
    "jQuery AJAX URL": re.compile(r"""\$?\.(?:ajax|get|post|getJSON)\s*\([^)]*url\s*:\s*['"]((?:[^'"\\]|\\.)+)['"]""")
}


app = typer.Typer(help=f"{APP_NAME} - A CLI tool to find URLs, potential secrets, and API endpoints in web content.")
console = Console()

def fetch_content(url: str, progress: Progress, task_id: TaskID) -> tuple[str | None, str | None, str]:
    headers = {"User-Agent": f"Mozilla/5.0 WebReconTool/{VERSION}"}
    description_prefix = f"Fetching {url[:50]}..."
    try:
        progress.update(task_id, description=description_prefix)
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "").lower()
        final_url = response.url
        progress.update(task_id, advance=1, description=f"Fetched [cyan]{final_url[:70]}[/cyan]")
        return response.text, content_type, final_url
    except requests.exceptions.RequestException as e:
        progress.update(task_id, advance=1, description=f"[red]Error {url[:50]}: {str(e)[:30]}[/red]")
        return None, None, url
    except Exception as e:
        progress.update(task_id, advance=1, description=f"[red]Unexpected error {url[:50]}: {str(e)[:30]}[/red]")
        return None, None, url

def fetch_content_for_check(url: str) -> tuple[str | None, str | None, str]:
    headers = {"User-Agent": f"Mozilla/5.0 WebReconTool/{VERSION}"}
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "").lower()
        return response.text, content_type, response.url
    except requests.exceptions.RequestException: return None, None, url
    except Exception: return None, None, url

def find_urls_and_apis(text: str, source_url: str, found_apis_set: set):
    discovered_urls_in_text = set()
    for match in re.finditer(URL_REGEX, text):
        url_candidate = match.group(0).strip().strip("'\"")
        if len(url_candidate) > 2048: continue
        url_candidate = re.sub(r'[;,)}\]\s]+$', '', url_candidate)
        final_url_to_validate = ""
        try:
            parsed_candidate = urlparse(url_candidate)
            if parsed_candidate.scheme and parsed_candidate.netloc:
                final_url_to_validate = url_candidate
            elif not parsed_candidate.scheme and (parsed_candidate.netloc or parsed_candidate.path):
                final_url_to_validate = urljoin(source_url, url_candidate)
            else: continue

            parsed_final = urlparse(final_url_to_validate)
            if parsed_final.scheme in ['http', 'https'] and parsed_final.netloc:
                if '\\' in parsed_final.netloc or ('\\' in parsed_final.path.split('?')[0].split('#')[0] and '\\\\' not in parsed_final.path and '\\u' not in parsed_final.path) :
                    continue
                discovered_urls_in_text.add(final_url_to_validate)
                if API_PATH_PATTERNS_REGEX.search(unquote(parsed_final.path)):
                    found_apis_set.add(final_url_to_validate)
        except ValueError: continue
        except Exception: continue
            
    is_likely_js = "script" in source_url.lower() or ".js" in source_url.lower() or text.strip().startswith(('function', 'var', 'let', 'const', '(', '{', 'window.', 'self.'))
    if is_likely_js:
        for pattern_name, compiled_regex in JS_API_CALL_PATTERNS_REGEX.items():
            for match in compiled_regex.finditer(text):
                js_url_match = match.group(1)
                if not js_url_match: continue
                js_url_candidate = js_url_match.strip().strip("'\"")
                js_url_candidate = re.sub(r'[;,)}\]\s]+$', '', js_url_candidate)
                if not js_url_candidate or len(js_url_candidate) > 2048: continue
                
                is_path_like = js_url_candidate.startswith(('/', './', '../')) or \
                               not re.match(r"^[a-zA-Z0-9]+:", js_url_candidate) # Not a scheme like 'javascript:'
                
                if not is_path_like and not js_url_candidate.startswith(('http','//')): # if not path like and not absolute, probably a variable name
                    if not re.search(r"[/?#=&%]", js_url_candidate): # if no common url chars, likely not a url
                        continue

                try:
                    resolved_js_api_url = urljoin(source_url, js_url_candidate)
                    parsed_js_api_url = urlparse(resolved_js_api_url)
                    if parsed_js_api_url.scheme in ['http', 'https'] and parsed_js_api_url.netloc:
                        discovered_urls_in_text.add(resolved_js_api_url)
                        found_apis_set.add(resolved_js_api_url)
                except ValueError: continue
                except Exception: continue
    return discovered_urls_in_text

def find_secrets(text: str, content_type: str, source_description: str) -> list[tuple[str, str, str, str]]:
    found_secrets_list = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if len(line.strip()) < 8 and not any(kw in line.lower() for kw in ['key', 'secret', 'token', 'pass', 'auth', '=:', 'http']):
            continue

        for secret_name, config in SECRET_PATTERNS.items():
            pattern_str = config["pattern"]
            value_group_idx = config.get("value_group", 0)

            try:
                for match in re.finditer(pattern_str, line):
                    full_match_value = match.group(0)
                    secret_value_candidate = full_match_value # Default to full match

                    if value_group_idx > 0 and value_group_idx <= len(match.groups()):
                        secret_value_candidate = match.group(value_group_idx)
                    
                    # Strip quotes for placeholder/common word check
                    cleaned_value = secret_value_candidate.strip("'\" ")

                    if PLACEHOLDER_REGEX.match(cleaned_value.upper()): # Check against upper for case-insensitivity of placeholder
                        continue
                    
                    if secret_name == "Password (High Confidence Variable Assignment)" and cleaned_value.lower() in COMMON_WORDS_FOR_PASSWORD_FP_CHECK:
                        continue
                    
                    if secret_name == "AWS Secret Access Key":
                        if len(set(cleaned_value)) < 5: # Very low entropy check
                            continue
                    
                    if secret_name == "Generic API Key (AlphaNum)" or secret_name == "API Key (Hexadecimal)":
                        if cleaned_value.lower().startswith(("test", "example", "sample", "dummy", "none", "null", "placeholder", "changeme")):
                            continue
                        if len(set(cleaned_value)) < 4 and len(cleaned_value) > 10: # Low entropy for a key
                             continue


                    context_start = max(0, i - 2)
                    context_end = min(len(lines), i + 3)
                    context = "\n".join(lines[context_start:context_end])
                    highlighted_context = context.replace(full_match_value, f"[bold yellow]{full_match_value}[/bold yellow]")
                    found_secrets_list.append(
                        (secret_name, full_match_value, source_description, highlighted_context)
                    )
            except re.error: continue
            except Exception: continue # General catch for unexpected issues in secret matching
    return found_secrets_list


def beautify_js(js_code: str) -> str:
    try: return jsbeautifier.beautify(js_code)
    except Exception: return js_code

@app.command()
def scan(
    target_url: str = typer.Argument(..., help="The base URL to start scanning from."),
    depth: int = typer.Option(1, "--depth", "-d", min=0, help="Crawling depth for linked pages. 0 means only the target_url."),
    scan_js: bool = typer.Option(True, "--scan-js/--no-scan-js", help="Scan linked JavaScript files."),
    scan_html_inline: bool = typer.Option(True, "--scan-html/--no-scan-html", help="Scan inline HTML content."),
    show_code_context: bool = typer.Option(False, "--show-context/--no-context", help="Show code context for found secrets."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save results to a file (e.g., results.txt).")
):
    console.rule(f"[bold blue]{APP_NAME} v{VERSION}[/bold blue] - Scanning: [cyan]{target_url}[/cyan]")

    all_found_urls = set()
    all_found_secrets = []
    all_found_api_endpoints = set()
    processed_urls = set()
    urls_to_scan = [(target_url, 0)]

    with Progress(console=console, transient=True) as progress:
        current_total_for_scan_task = len(urls_to_scan)
        scan_task = progress.add_task("[yellow]Scanning URLs...", total=current_total_for_scan_task)

        while urls_to_scan:
            current_url, current_depth = urls_to_scan.pop(0)
            if current_url in processed_urls:
                if not progress.tasks[scan_task].finished and progress.tasks[scan_task].completed < progress.tasks[scan_task].total:
                     progress.update(scan_task, advance=1, description=f"Skipped [dim]{current_url[:50]}[/dim]")
                continue
            processed_urls.add(current_url)
            
            content, content_type, effective_url = fetch_content(current_url, progress, scan_task)
            if not content: continue

            parsed_effective_url = urlparse(effective_url)
            if parsed_effective_url.scheme and parsed_effective_url.netloc:
                 all_found_urls.add(effective_url)
                 if API_PATH_PATTERNS_REGEX.search(unquote(parsed_effective_url.path)):
                     all_found_api_endpoints.add(effective_url)

            source_desc_for_find_urls = effective_url # For JS API calls, source_url is the JS file itself

            if 'html' in (content_type or "") and scan_html_inline:
                progress.update(scan_task, description=f"Parsing HTML: {effective_url[:50]}...")
                soup = BeautifulSoup(content, 'html.parser')
                for tag in soup.find_all(['a', 'link'], href=True):
                    try:
                        link_href = tag['href']
                        if not isinstance(link_href, str) or link_href.startswith(('javascript:', 'mailto:', 'tel:')): continue
                        link = urljoin(effective_url, link_href)
                        parsed_link = urlparse(link)
                        if parsed_link.scheme in ['http', 'https'] and parsed_link.netloc:
                            all_found_urls.add(link)
                            if API_PATH_PATTERNS_REGEX.search(unquote(parsed_link.path)): all_found_api_endpoints.add(link)
                            if current_depth < depth and link not in processed_urls and link not in [u[0] for u in urls_to_scan]:
                                urls_to_scan.append((link, current_depth + 1))
                                current_total_for_scan_task += 1
                                progress.update(scan_task, total=current_total_for_scan_task)
                    except Exception: continue
                for tag in soup.find_all(['script', 'img', 'iframe', 'source', 'embed', 'video', 'audio', 'track'], src=True): # Added more media tags
                    try:
                        item_src = tag['src']
                        if not isinstance(item_src, str): continue
                        item_url = urljoin(effective_url, item_src)
                        parsed_item_url = urlparse(item_url)
                        if parsed_item_url.scheme in ['http', 'https'] and parsed_item_url.netloc:
                            all_found_urls.add(item_url)
                            if API_PATH_PATTERNS_REGEX.search(unquote(parsed_item_url.path)): all_found_api_endpoints.add(item_url)
                            if tag.name == 'script' and scan_js and item_url not in processed_urls and item_url not in [u[0] for u in urls_to_scan]:
                                js_text_check, js_content_type_check, _ = fetch_content_for_check(item_url)
                                if js_text_check and js_content_type_check and ('javascript' in (js_content_type_check or "") or 'application/x-javascript' in (js_content_type_check or "")):
                                    urls_to_scan.append((item_url, current_depth))
                                    current_total_for_scan_task += 1
                                    progress.update(scan_task, total=current_total_for_scan_task)
                    except Exception: continue
                
                html_text_content = soup.get_text(separator=' ', strip=True)
                all_found_urls.update(find_urls_and_apis(html_text_content, effective_url, all_found_api_endpoints))
                secrets_in_html = find_secrets(content, "HTML", f"Inline HTML of {effective_url}")
                if secrets_in_html:
                    progress.print(f"[yellow]Found {len(secrets_in_html)} potential secret(s) in inline HTML of [cyan]{effective_url}[/cyan]")
                    all_found_secrets.extend(secrets_in_html)
                
                for script_tag in soup.find_all('script'):
                    if script_tag.string:
                        js_code = beautify_js(script_tag.string)
                        all_found_urls.update(find_urls_and_apis(js_code, effective_url, all_found_api_endpoints))
                        secrets_in_inline_js = find_secrets(js_code, "Inline JavaScript", f"Inline JS in {effective_url}")
                        if secrets_in_inline_js:
                            progress.print(f"[yellow]Found {len(secrets_in_inline_js)} potential secret(s) in inline JS of [cyan]{effective_url}[/cyan]")
                            all_found_secrets.extend(secrets_in_inline_js)

            elif ('javascript' in (content_type or "") or \
                  'application/x-javascript' in (content_type or "") or \
                  (content_type is None and effective_url.lower().endswith(('.js', '.mjs')))) and scan_js:
                progress.update(scan_task, description=f"Analyzing JS: {effective_url[:50]}...")
                js_code = beautify_js(content)
                all_found_urls.update(find_urls_and_apis(js_code, effective_url, all_found_api_endpoints)) # Pass effective_url of the JS file
                secrets_in_js = find_secrets(js_code, "JavaScript", f"File: {effective_url}")
                if secrets_in_js:
                    progress.print(f"[yellow]Found {len(secrets_in_js)} potential secret(s) in [cyan]{effective_url}[/cyan]")
                    all_found_secrets.extend(secrets_in_js)
            elif content:
                progress.update(scan_task, description=f"Generic scan: {effective_url[:50]}...")
                all_found_urls.update(find_urls_and_apis(content, effective_url, all_found_api_endpoints))
                other_secrets = find_secrets(content, content_type if content_type else "Unknown", f"File: {effective_url}")
                if other_secrets:
                    progress.print(f"[yellow]Found {len(other_secrets)} potential secret(s) in [cyan]{effective_url}[/cyan] (Type: {content_type})")
                    all_found_secrets.extend(other_secrets)
        
        if not progress.tasks[scan_task].finished:
             progress.update(scan_task, completed=current_total_for_scan_task, description="[green]Scan Complete![/green]")

    output_buffer = []
    if all_found_urls:
        console.rule("[bold green]Discovered URLs[/bold green]")
        output_buffer.append("\n--- Discovered URLs ---\n")
        url_table = Table(show_header=True, header_style="bold magenta")
        url_table.add_column("N", style="dim", width=4); url_table.add_column("URL", style="cyan")
        for i, url_item in enumerate(sorted(list(all_found_urls)), 1):
            url_table.add_row(str(i), url_item); output_buffer.append(f"{i}. {url_item}\n")
        console.print(url_table)
    else:
        msg = "[yellow]No URLs found.[/yellow]"; console.print(msg); output_buffer.append(msg + "\n")

    if all_found_api_endpoints:
        console.rule("[bold yellow]Potential API/Backend Endpoints[/bold yellow]")
        output_buffer.append("\n--- Potential API/Backend Endpoints ---\n")
        api_table = Table(show_header=True, header_style="bold yellow")
        api_table.add_column("N", style="dim", width=4); api_table.add_column("Endpoint URL", style="cyan")
        for i, api_item in enumerate(sorted(list(all_found_api_endpoints)), 1):
            api_table.add_row(str(i), api_item); output_buffer.append(f"{i}. {api_item}\n")
        console.print(api_table)
    else:
        msg = "[green]No potential API/Backend Endpoints found.[/green]"; console.print(msg); output_buffer.append(msg + "\n")

    if all_found_secrets:
        console.rule("[bold red]Potential Secrets Found[/bold red]")
        output_buffer.append("\n--- Potential Secrets Found ---\n")
        secrets_table = Table(show_header=True, header_style="bold red")
        secrets_table.add_column("N", style="dim", width=4); secrets_table.add_column("Type", style="yellow", width=40) # Increased width for type
        secrets_table.add_column("Value (Excerpt)", style="red"); secrets_table.add_column("Source", style="blue")
        for i, (name, value, source, context) in enumerate(all_found_secrets, 1):
            display_value = (value[:75] + '...') if len(value) > 75 else value
            secrets_table.add_row(str(i), name, display_value, source)
            output_buffer.append(f"\n{i}. Type: {name}\n   Value: {value}\n   Source: {source}\n")
            if show_code_context and context:
                output_buffer.append("   Context:\n")
                panel_content = Syntax(context, "javascript" if "javascript" in source.lower() or ".js" in source.lower() else "html", theme="monokai", line_numbers=True, word_wrap=True)
                panel = Panel(panel_content, title=f"Context for Secret #{i} from {source}", border_style="dim yellow", expand=False)
                console.print(panel); output_buffer.append(context + "\n")
            elif context and not show_code_context:
                 output_buffer.append("   Context (run with --show-context to display):\n"); output_buffer.append(context + "\n")
        console.print(secrets_table)
        console.print("\n[bold yellow]WARNING:[/bold yellow] Secret detection may include false positives. Always verify findings.")
        output_buffer.append("\nWARNING: Secret detection may include false positives. Always verify findings.\n")
    else:
        msg = "[green]No potential secrets found.[/green]"; console.print(msg); output_buffer.append(msg + "\n")

    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"{APP_NAME} v{VERSION} - Scan Report for: {target_url}\n"); f.write("=" * 50 + "\n")
                f.writelines(output_buffer)
            console.print(f"\n[bold green]Results saved to {output_file}[/bold green]")
        except IOError as e: console.print(f"\n[bold red]Error saving results to {output_file}: {e}[/bold red]")
    console.rule(f"[bold blue]Scan Finished for: [cyan]{target_url}[/cyan][/bold blue]")

@app.callback()
def main(version: bool = typer.Option(None, "--version", "-v", is_eager=True, help=f"Show {APP_NAME} version and exit.")):
    if version: console.print(f"[bold green]{APP_NAME} version: {VERSION}[/bold green]"); raise typer.Exit()

if __name__ == "__main__":
    app()