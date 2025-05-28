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
import jsbeautifier
from urllib.parse import urljoin, urlparse, unquote
import math
import json
import os
from pathlib import Path
from collections import Counter
from typing import Dict, List, Tuple, Set, Optional

# --- Configuration ---
APP_NAME = "Web Recon Tool"
VERSION = "0.5.0"  # Separate files version

# --- Global Variables ---
console = Console()
SECRET_PATTERNS = {}
API_CONFIG = {}
JS_CONFIG = {}
API_PATTERNS = None
JS_PATTERNS = {}

def load_json_file(filename: str, description: str) -> Dict:
    """Load JSON file with fallback paths."""
    script_dir = Path(__file__).parent
    possible_paths = [
        script_dir / filename,
        Path(filename),
        script_dir / "patterns" / filename,
        Path("patterns") / filename
    ]
    
    for file_path in possible_paths:
        try:
            if file_path.exists():
                console.print(f"[dim]Loading {description} from: {file_path}[/dim]")
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Extract patterns from metadata structure if present
                if '_metadata' in data:
                    # Remove metadata for processing
                    patterns = {k: v for k, v in data.items() if not k.startswith('_')}
                    metadata = data['_metadata']
                    total_patterns = metadata.get('total_patterns', len(patterns))
                    version = metadata.get('version', 'unknown')
                    console.print(f"[green]Loaded {total_patterns} {description} v{version} from {file_path.name}[/green]")
                    return patterns
                else:
                    console.print(f"[green]Loaded {description} from {file_path.name}[/green]")
                    return data
                    
        except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
            console.print(f"[yellow]Warning: Could not load {file_path}: {e}[/yellow]")
            continue
        except Exception as e:
            console.print(f"[yellow]Unexpected error loading {file_path}: {e}[/yellow]")
            continue
    
    console.print(f"[yellow]No {description} file found. Using fallback patterns.[/yellow]")
    return {}

def load_patterns_from_files() -> Tuple[Dict, Dict, Dict]:
    """Load patterns from separate JSON files."""
    
    # Load secret patterns
    secret_patterns = load_json_file("secret_patterns.json", "secret patterns")
    if not secret_patterns:
        secret_patterns = {
            "AWS Access Key ID": {
                "pattern": r"(A[SK]IA[0-9A-Z]{16})",
                "value_group": 1,
                "desc": "Amazon Web Services Access Key ID.",
                "confidence": "high"
            }
        }
    
    # Load API patterns
    api_patterns = load_json_file("api_patterns.json", "API patterns")
    if not api_patterns:
        api_patterns = {
            "standard_api_paths": {"patterns": ["/api", "/v1", "/rest"]},
            "admin_paths": {"patterns": ["/admin", "/dashboard"]}
        }
    
    # Load JS API patterns
    js_patterns = load_json_file("js_api_patterns.json", "JavaScript API patterns")
    if not js_patterns:
        js_patterns = {
            "fetch_patterns": {"patterns": ["fetch\\s*\\(\\s*['\"]([^'\"]+)['\"]"]},
            "axios_patterns": {"patterns": ["axios\\.\\w+\\s*\\(\\s*['\"]([^'\"]+)['\"]"]}
        }
    
    return secret_patterns, api_patterns, js_patterns

def compile_api_patterns(api_config: Dict) -> re.Pattern:
    """Compile API endpoint patterns from configuration."""
    all_patterns = []
    
    for category, config in api_config.items():
        if isinstance(config, dict) and 'patterns' in config:
            patterns = config['patterns']
            if isinstance(patterns, list):
                all_patterns.extend(patterns)
        elif isinstance(config, list):
            # Fallback for old format
            all_patterns.extend(config)
    
    if not all_patterns:
        # Fallback patterns
        all_patterns = ["/api", "/v[1-9]", "/admin", "\\.json"]
    
    # Join all patterns with OR operator
    combined_pattern = "(?:" + ")|(?:".join(all_patterns) + ")"
    
    try:
        return re.compile(combined_pattern, re.VERBOSE | re.IGNORECASE)
    except re.error as e:
        console.print(f"[red]Error compiling API patterns: {e}[/red]")
        # Return a basic fallback pattern
        return re.compile(r"(?:/api)|(?:/v[1-9])", re.IGNORECASE)

def compile_js_patterns(js_config: Dict) -> Dict[str, re.Pattern]:
    """Compile JavaScript API call patterns from configuration."""
    compiled_patterns = {}
    
    for category, config in js_config.items():
        if isinstance(config, dict) and 'patterns' in config:
            patterns = config['patterns']
            if isinstance(patterns, list):
                for i, pattern in enumerate(patterns):
                    try:
                        pattern_name = f"{category}_{i+1}"
                        compiled_patterns[pattern_name] = re.compile(pattern, re.IGNORECASE)
                    except re.error as e:
                        console.print(f"[yellow]Skipping invalid JS pattern {pattern}: {e}[/yellow]")
                        continue
        elif isinstance(config, list):
            # Fallback for old format
            for i, pattern in enumerate(config):
                try:
                    pattern_name = f"{category}_{i+1}"
                    compiled_patterns[pattern_name] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    console.print(f"[yellow]Skipping invalid JS pattern {pattern}: {e}[/yellow]")
                    continue
    
    # Fallback if no patterns loaded
    if not compiled_patterns:
        compiled_patterns = {
            "fetch": re.compile(r"fetch\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
            "axios": re.compile(r"axios\.\w+\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
        }
    
    return compiled_patterns

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if len(data) == 0:
        return 0.0
    
    counter = Counter(data)
    length = len(data)
    
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def is_likely_false_positive(secret_name: str, value: str, context: str = "") -> bool:
    """Enhanced false positive detection."""
    cleaned_value = value.strip("'\" ")
    lower_value = cleaned_value.lower()
    
    # Common false positive indicators
    fp_indicators = [
        "test", "example", "sample", "dummy", "fake", "mock", "placeholder",
        "changeme", "password123", "123456", "qwerty", "admin", "root"
    ]
    
    if lower_value in fp_indicators:
        return True
    
    # Check for obvious test patterns
    test_patterns = [
        r'^(test|example|sample|dummy|fake|mock)',
        r'^(abc|xyz|foo|bar|baz)',
        r'^1+$|^0+$|^a+$',
        r'qwerty|asdfgh'
    ]
    
    for pattern in test_patterns:
        if re.search(pattern, lower_value):
            return True
    
    # Enhanced entropy checks
    pattern_config = SECRET_PATTERNS.get(secret_name, {})
    min_entropy = pattern_config.get("min_entropy", 0)
    
    if min_entropy > 0:
        entropy = calculate_entropy(cleaned_value)
        if entropy < min_entropy:
            return True
    
    # Context-based validation
    context_lower = context.lower()
    false_positive_contexts = [
        'example', 'sample', 'demo', 'test', 'placeholder', 'comment', 
        'documentation', 'readme', 'tutorial', 'guide'
    ]
    
    for fp_context in false_positive_contexts:
        if fp_context in context_lower:
            return True
    
    return False

def fetch_content(url: str, progress: Progress, task_id: TaskID) -> Tuple[Optional[str], Optional[str], str]:
    """Fetch web content with enhanced headers."""
    headers = {
        "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WebReconTool/{VERSION}",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    try:
        progress.update(task_id, description=f"Fetching {url[:50]}...")
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

def is_valid_url(url: str) -> bool:
    """Enhanced URL validation."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme in ['http', 'https']:
            return False
        if not parsed.netloc:
            return False
        if '\\' in parsed.netloc:
            return False
        if parsed.netloc.count('.') > 10:
            return False
        
        path_part = parsed.path.split('?')[0].split('#')[0]
        if '\\\\' not in parsed.path and '\\u' not in parsed.path and '\\' in path_part:
            return False
            
        return True
    except Exception:
        return False

def find_urls_and_apis(text: str, source_url: str, found_apis_set: Set[str]) -> Set[str]:
    """Find URLs and API endpoints using configurable patterns."""
    discovered_urls = set()
    
    # Standard URL regex
    url_regex = r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»""'']))"""
    
    for match in re.finditer(url_regex, text):
        url_candidate = match.group(0).strip().strip("'\"")
        if len(url_candidate) > 2048:
            continue
            
        url_candidate = re.sub(r'[;,)}\]\s]+$', '', url_candidate)
        
        try:
            parsed_candidate = urlparse(url_candidate)
            final_url = ""
            
            if parsed_candidate.scheme and parsed_candidate.netloc:
                final_url = url_candidate
            elif not parsed_candidate.scheme and (parsed_candidate.netloc or parsed_candidate.path):
                final_url = urljoin(source_url, url_candidate)
            else:
                continue

            if is_valid_url(final_url):
                discovered_urls.add(final_url)
                parsed_final = urlparse(final_url)
                if API_PATTERNS.search(unquote(parsed_final.path)):
                    found_apis_set.add(final_url)
        except Exception:
            continue
    
    # JavaScript API call detection
    is_likely_js = any(indicator in source_url.lower() for indicator in ['.js', 'script']) or \
                   text.strip().startswith(('function', 'var', 'let', 'const', '(', '{', 'window.', 'self.'))
    
    if is_likely_js and JS_PATTERNS:
        for pattern_name, compiled_pattern in JS_PATTERNS.items():
            for match in compiled_pattern.finditer(text):
                # Extract URL from different capture groups
                js_url_match = None
                for group_idx in range(1, len(match.groups()) + 1):
                    if match.group(group_idx):
                        js_url_match = match.group(group_idx)
                        break
                
                if not js_url_match:
                    continue
                    
                js_url_candidate = js_url_match.strip().strip("'\"")
                if not js_url_candidate or len(js_url_candidate) > 2048:
                    continue
                
                try:
                    resolved_url = urljoin(source_url, js_url_candidate)
                    if is_valid_url(resolved_url):
                        discovered_urls.add(resolved_url)
                        found_apis_set.add(resolved_url)
                except Exception:
                    continue
    
    return discovered_urls

def find_secrets(text: str, content_type: str, source_description: str) -> List[Tuple[str, str, str, str, str]]:
    """Find secrets using configurable patterns."""
    found_secrets = []
    lines = text.splitlines()
    
    for i, line in enumerate(lines):
        if len(line.strip()) < 6:
            continue

        for secret_name, config in SECRET_PATTERNS.items():
            pattern_str = config["pattern"]
            value_group_idx = config.get("value_group", 0)
            confidence = config.get("confidence", "medium")

            try:
                for match in re.finditer(pattern_str, line):
                    full_match = match.group(0)
                    secret_value = full_match
                    
                    if value_group_idx > 0 and value_group_idx <= len(match.groups()):
                        secret_value = match.group(value_group_idx)
                    
                    # Context extraction
                    context_start = max(0, i - 2)
                    context_end = min(len(lines), i + 3)
                    context = "\n".join(lines[context_start:context_end])
                    
                    # Enhanced false positive detection
                    if is_likely_false_positive(secret_name, secret_value, context):
                        continue
                    
                    highlighted_context = context.replace(full_match, f"[bold yellow]{full_match}[/bold yellow]")
                    found_secrets.append(
                        (secret_name, full_match, source_description, highlighted_context, confidence)
                    )
            except re.error:
                continue
            except Exception:
                continue
                
    return found_secrets

def beautify_js(js_code: str) -> str:
    """Beautify JavaScript code for better analysis."""
    try:
        return jsbeautifier.beautify(js_code, {
            'indent_size': 2,
            'max_preserve_newlines': 2,
            'preserve_newlines': True,
            'keep_array_indentation': False,
            'break_chained_methods': False,
            'space_before_conditional': True
        })
    except Exception:
        return js_code

def categorize_endpoints(endpoints: Set[str]) -> Dict[str, Set[str]]:
    """Categorize API endpoints using configuration."""
    categories = {
        "Authentication": set(),
        "Admin/Management": set(),
        "API/Services": set(),
        "File Operations": set(),
        "Monitoring/Health": set(),
        "Documentation": set(),
        "Webhooks/Callbacks": set(),
        "Other": set()
    }
    
    # Get patterns from API patterns configuration
    category_mapping = {
        "Authentication": API_CONFIG.get('auth_paths', {}).get('patterns', []),
        "Admin/Management": API_CONFIG.get('admin_paths', {}).get('patterns', []),
        "API/Services": API_CONFIG.get('standard_api_paths', {}).get('patterns', []),
        "File Operations": API_CONFIG.get('file_operations', {}).get('patterns', []),
        "Monitoring/Health": API_CONFIG.get('monitoring_paths', {}).get('patterns', []),
        "Documentation": API_CONFIG.get('documentation_paths', {}).get('patterns', []),
        "Webhooks/Callbacks": API_CONFIG.get('webhook_paths', {}).get('patterns', [])
    }
    
    for endpoint in endpoints:
        categorized = False
        for category, patterns in category_mapping.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, endpoint, re.IGNORECASE):
                        categories[category].add(endpoint)
                        categorized = True
                        break
                except re.error:
                    continue
            if categorized:
                break
        
        if not categorized:
            categories["Other"].add(endpoint)
    
    return {k: v for k, v in categories.items() if v}

# Initialize configuration from separate files
SECRET_PATTERNS, API_CONFIG, JS_CONFIG = load_patterns_from_files()
API_PATTERNS = compile_api_patterns(API_CONFIG)
JS_PATTERNS = compile_js_patterns(JS_CONFIG)

app = typer.Typer(help=f"{APP_NAME} - Modular reconnaissance tool with separate pattern files.")

@app.command()
def scan(
    target_url: str = typer.Argument(..., help="The base URL to start scanning from."),
    depth: int = typer.Option(1, "--depth", "-d", min=0, help="Crawling depth for linked pages."),
    scan_js: bool = typer.Option(True, "--scan-js/--no-scan-js", help="Scan linked JavaScript files."),
    scan_html_inline: bool = typer.Option(True, "--scan-html/--no-scan-html", help="Scan inline HTML content."),
    show_code_context: bool = typer.Option(False, "--show-context/--no-context", help="Show code context for secrets."),
    min_confidence: str = typer.Option("low", "--min-confidence", help="Minimum confidence level (low/medium/high)."),
    categorize_apis: bool = typer.Option(True, "--categorize-apis/--no-categorize-apis", help="Categorize API endpoints."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save results to file."),
    reload_patterns: bool = typer.Option(False, "--reload-patterns", help="Reload pattern files before scanning.")
):
    """Enhanced web reconnaissance with separate pattern files."""
    
    # Reload patterns if requested
    if reload_patterns:
        global SECRET_PATTERNS, API_CONFIG, JS_CONFIG, API_PATTERNS, JS_PATTERNS
        console.print("[blue]Reloading pattern files...[/blue]")
        SECRET_PATTERNS, API_CONFIG, JS_CONFIG = load_patterns_from_files()
        API_PATTERNS = compile_api_patterns(API_CONFIG)
        JS_PATTERNS = compile_js_patterns(JS_CONFIG)
    
    console.rule(f"[bold blue]{APP_NAME} v{VERSION}[/bold blue] - Scanning: [cyan]{target_url}[/cyan]")
    
    confidence_levels = {"low": 0, "medium": 1, "high": 2}
    min_conf_level = confidence_levels.get(min_confidence.lower(), 0)

    all_found_urls = set()
    all_found_secrets = []
    all_found_api_endpoints = set()
    processed_urls = set()
    urls_to_scan = [(target_url, 0)]

    with Progress(console=console, transient=True) as progress:
        current_total = len(urls_to_scan)
        scan_task = progress.add_task("[yellow]Scanning URLs...", total=current_total)

        while urls_to_scan:
            current_url, current_depth = urls_to_scan.pop(0)
            if current_url in processed_urls:
                if not progress.tasks[scan_task].finished and progress.tasks[scan_task].completed < progress.tasks[scan_task].total:
                     progress.update(scan_task, advance=1, description=f"Skipped [dim]{current_url[:50]}[/dim]")
                continue
            processed_urls.add(current_url)
            
            content, content_type, effective_url = fetch_content(current_url, progress, scan_task)
            if not content:
                continue

            parsed_effective_url = urlparse(effective_url)
            if parsed_effective_url.scheme and parsed_effective_url.netloc:
                 all_found_urls.add(effective_url)
                 if API_PATTERNS.search(unquote(parsed_effective_url.path)):
                     all_found_api_endpoints.add(effective_url)

            if 'html' in (content_type or "") and scan_html_inline:
                progress.update(scan_task, description=f"Parsing HTML: {effective_url[:50]}...")
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract links and resources
                for tag in soup.find_all(['a', 'link'], href=True):
                    try:
                        link_href = tag['href']
                        if not isinstance(link_href, str) or link_href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                            continue
                        link = urljoin(effective_url, link_href)
                        if is_valid_url(link):
                            all_found_urls.add(link)
                            parsed_link = urlparse(link)
                            if API_PATTERNS.search(unquote(parsed_link.path)):
                                all_found_api_endpoints.add(link)
                            if current_depth < depth and link not in processed_urls and link not in [u[0] for u in urls_to_scan]:
                                urls_to_scan.append((link, current_depth + 1))
                                current_total += 1
                                progress.update(scan_task, total=current_total)
                    except Exception:
                        continue
                
                # Extract resources
                resource_tags = ['script', 'img', 'iframe', 'source', 'embed', 'video', 'audio', 'track', 'object', 'frame']
                for tag in soup.find_all(resource_tags, src=True):
                    try:
                        item_src = tag['src']
                        if not isinstance(item_src, str):
                            continue
                        item_url = urljoin(effective_url, item_src)
                        if is_valid_url(item_url):
                            all_found_urls.add(item_url)
                            parsed_item_url = urlparse(item_url)
                            if API_PATTERNS.search(unquote(parsed_item_url.path)):
                                all_found_api_endpoints.add(item_url)
                            if tag.name == 'script' and scan_js and item_url not in processed_urls and item_url not in [u[0] for u in urls_to_scan]:
                                urls_to_scan.append((item_url, current_depth))
                                current_total += 1
                                progress.update(scan_task, total=current_total)
                    except Exception:
                        continue
                
                # URL and API detection in HTML text
                html_text_content = soup.get_text(separator=' ', strip=True)
                all_found_urls.update(find_urls_and_apis(html_text_content, effective_url, all_found_api_endpoints))
                
                # Secret detection in HTML
                secrets_in_html = find_secrets(content, "HTML", f"Inline HTML of {effective_url}")
                filtered_secrets = [s for s in secrets_in_html if confidence_levels.get(s[4], 0) >= min_conf_level]
                if filtered_secrets:
                    progress.print(f"[yellow]Found {len(filtered_secrets)} potential secret(s) in HTML of [cyan]{effective_url}[/cyan]")
                    all_found_secrets.extend(filtered_secrets)
                
                # Inline JavaScript analysis
                for script_tag in soup.find_all('script'):
                    if script_tag.string:
                        js_code = beautify_js(script_tag.string)
                        all_found_urls.update(find_urls_and_apis(js_code, effective_url, all_found_api_endpoints))
                        secrets_in_inline_js = find_secrets(js_code, "Inline JavaScript", f"Inline JS in {effective_url}")
                        filtered_js_secrets = [s for s in secrets_in_inline_js if confidence_levels.get(s[4], 0) >= min_conf_level]
                        if filtered_js_secrets:
                            progress.print(f"[yellow]Found {len(filtered_js_secrets)} potential secret(s) in inline JS of [cyan]{effective_url}[/cyan]")
                            all_found_secrets.extend(filtered_js_secrets)

            elif ('javascript' in (content_type or "") or \
                  'application/x-javascript' in (content_type or "") or \
                  (content_type is None and effective_url.lower().endswith(('.js', '.mjs')))) and scan_js:
                progress.update(scan_task, description=f"Analyzing JS: {effective_url[:50]}...")
                js_code = beautify_js(content)
                all_found_urls.update(find_urls_and_apis(js_code, effective_url, all_found_api_endpoints))
                secrets_in_js = find_secrets(js_code, "JavaScript", f"File: {effective_url}")
                filtered_js_secrets = [s for s in secrets_in_js if confidence_levels.get(s[4], 0) >= min_conf_level]
                if filtered_js_secrets:
                    progress.print(f"[yellow]Found {len(filtered_js_secrets)} potential secret(s) in [cyan]{effective_url}[/cyan]")
                    all_found_secrets.extend(filtered_js_secrets)
                    
            elif content:
                progress.update(scan_task, description=f"Generic scan: {effective_url[:50]}...")
                all_found_urls.update(find_urls_and_apis(content, effective_url, all_found_api_endpoints))
                other_secrets = find_secrets(content, content_type if content_type else "Unknown", f"File: {effective_url}")
                filtered_other_secrets = [s for s in other_secrets if confidence_levels.get(s[4], 0) >= min_conf_level]
                if filtered_other_secrets:
                    progress.print(f"[yellow]Found {len(filtered_other_secrets)} potential secret(s) in [cyan]{effective_url}[/cyan]")
                    all_found_secrets.extend(filtered_other_secrets)
        
        if not progress.tasks[scan_task].finished:
             progress.update(scan_task, completed=current_total, description="[green]Scan Complete![/green]")

    # Display results (same as before)
    output_buffer = []
    
    # URLs
    if all_found_urls:
        console.rule("[bold green]Discovered URLs[/bold green]")
        output_buffer.append(f"\n--- Discovered URLs ({len(all_found_urls)}) ---\n")
        url_table = Table(show_header=True, header_style="bold magenta")
        url_table.add_column("N", style="dim", width=4)
        url_table.add_column("URL", style="cyan")
        
        for i, url_item in enumerate(sorted(list(all_found_urls)), 1):
            url_table.add_row(str(i), url_item)
            output_buffer.append(f"{i}. {url_item}\n")
        console.print(url_table)
    else:
        msg = "[yellow]No URLs found.[/yellow]"
        console.print(msg)
        output_buffer.append(msg + "\n")

    # API Endpoints
    if all_found_api_endpoints:
        console.rule("[bold yellow]API/Backend Endpoints[/bold yellow]")
        output_buffer.append(f"\n--- API/Backend Endpoints ({len(all_found_api_endpoints)}) ---\n")
        
        if categorize_apis:
            categorized_endpoints = categorize_endpoints(all_found_api_endpoints)
            
            for category, endpoints in categorized_endpoints.items():
                if endpoints:
                    console.print(f"\n[bold blue]{category} ({len(endpoints)})[/bold blue]")
                    output_buffer.append(f"\n{category} ({len(endpoints)}):\n")
                    
                    category_table = Table(show_header=False, box=None, padding=(0, 2))
                    category_table.add_column("N", style="dim", width=4)
                    category_table.add_column("Endpoint", style="cyan")
                    
                    for i, endpoint in enumerate(sorted(endpoints), 1):
                        category_table.add_row(str(i), endpoint)
                        output_buffer.append(f"  {i}. {endpoint}\n")
                    console.print(category_table)
        else:
            api_table = Table(show_header=True, header_style="bold yellow")
            api_table.add_column("N", style="dim", width=4)
            api_table.add_column("Endpoint URL", style="cyan")
            
            for i, api_item in enumerate(sorted(list(all_found_api_endpoints)), 1):
                api_table.add_row(str(i), api_item)
                output_buffer.append(f"{i}. {api_item}\n")
            console.print(api_table)
    else:
        msg = "[green]No API endpoints found.[/green]"
        console.print(msg)
        output_buffer.append(msg + "\n")

    # Secrets
    if all_found_secrets:
        console.rule("[bold red]Potential Secrets Found[/bold red]")
        output_buffer.append(f"\n--- Potential Secrets Found ({len(all_found_secrets)}) ---\n")
        
        # Group by confidence
        secrets_by_confidence = {"high": [], "medium": [], "low": []}
        for secret in all_found_secrets:
            confidence = secret[4] if len(secret) > 4 else "medium"
            secrets_by_confidence[confidence].append(secret)
        
        for conf_level in ["high", "medium", "low"]:
            secrets = secrets_by_confidence[conf_level]
            if not secrets:
                continue
                
            color_map = {"high": "red", "medium": "yellow", "low": "blue"}
            console.print(f"\n[bold {color_map[conf_level]}]{conf_level.upper()} CONFIDENCE ({len(secrets)})[/bold {color_map[conf_level]}]")
            output_buffer.append(f"\n{conf_level.upper()} CONFIDENCE ({len(secrets)}):\n")
            
            secrets_table = Table(show_header=True, header_style=f"bold {color_map[conf_level]}")
            secrets_table.add_column("N", style="dim", width=4)
            secrets_table.add_column("Type", style="yellow", width=35)
            secrets_table.add_column("Value (Excerpt)", style=color_map[conf_level])
            secrets_table.add_column("Source", style="blue")
            
            for i, (name, value, source, context, confidence) in enumerate(secrets, 1):
                display_value = (value[:60] + '...') if len(value) > 60 else value
                secrets_table.add_row(str(i), name, display_value, source)
                output_buffer.append(f"\n{i}. Type: {name}\n   Value: {value}\n   Source: {source}\n   Confidence: {confidence}\n")
                
                if show_code_context and context:
                    output_buffer.append("   Context:\n")
                    panel_content = Syntax(context, "javascript" if "javascript" in source.lower() or ".js" in source.lower() else "html", theme="monokai", line_numbers=True, word_wrap=True)
                    panel = Panel(panel_content, title=f"Context for Secret #{i} from {source}", border_style=f"dim {color_map[conf_level]}", expand=False)
                    console.print(panel)
                    output_buffer.append(context + "\n")
                elif context and not show_code_context:
                     output_buffer.append("   Context (run with --show-context to display):\n")
                     output_buffer.append(context + "\n")
            
            console.print(secrets_table)
        
        console.print(f"\n[bold yellow]WARNING:[/bold yellow] Secret detection may include false positives. Always verify findings.")
        console.print(f"[dim]Filter by confidence level using --min-confidence (low/medium/high)[/dim]")
        output_buffer.append("\nWARNING: Secret detection may include false positives. Always verify findings.\n")
    else:
        msg = "[green]No potential secrets found.[/green]"
        console.print(msg)
        output_buffer.append(msg + "\n")

    # Save results
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"{APP_NAME} v{VERSION} - Modular Scan Report\n")
                f.write("=" * 70 + "\n")
                f.write(f"Target: {target_url}\n")
                f.write(f"Configuration: {len(SECRET_PATTERNS)} secret patterns, {len(API_CONFIG)} API categories\n")
                f.write(f"Scan Settings: depth={depth}, js={scan_js}, html={scan_html_inline}\n")
                f.write("\n")
                f.writelines(output_buffer)
            console.print(f"\n[bold green]Results saved to {output_file}[/bold green]")
        except IOError as e:
            console.print(f"\n[bold red]Error saving results: {e}[/bold red]")
    
    # Summary
    console.rule("[bold blue]Scan Summary[/bold blue]")
    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Metric", style="bold cyan")
    summary_table.add_column("Count", style="bold green")
    summary_table.add_row("URLs Discovered", str(len(all_found_urls)))
    summary_table.add_row("API Endpoints", str(len(all_found_api_endpoints)))
    summary_table.add_row("Potential Secrets", str(len(all_found_secrets)))
    summary_table.add_row("Pages Processed", str(len(processed_urls)))
    summary_table.add_row("Secret Patterns", str(len(SECRET_PATTERNS)))
    summary_table.add_row("API Categories", str(len(API_CONFIG)))
    summary_table.add_row("JS Patterns", str(sum(len(config.get('patterns', [])) for config in JS_CONFIG.values() if isinstance(config, dict))))
    console.print(summary_table)
    
    console.rule(f"[bold blue]Scan Complete: [cyan]{target_url}[/cyan][/bold blue]")

@app.command()
def patterns(
    list_patterns: bool = typer.Option(False, "--list", "-l", help="List all loaded secret patterns."),
    list_api: bool = typer.Option(False, "--list-api", help="List API endpoint patterns."),
    list_js: bool = typer.Option(False, "--list-js", help="List JavaScript patterns."),
    show_stats: bool = typer.Option(False, "--stats", "-s", help="Show pattern statistics."),
    validate: bool = typer.Option(False, "--validate", "-v", help="Validate all pattern files."),
    category: str = typer.Option(None, "--category", "-c", help="Filter patterns by category.")
):
    """Manage and view patterns from separate files."""
    
    if validate:
        console.print(f"[bold blue]Validating Pattern Files[/bold blue]")
        
        # Validate secret patterns
        errors = 0
        console.print(f"\n[bold cyan]Secret Patterns Validation[/bold cyan]")
        for name, pattern_config in SECRET_PATTERNS.items():
            try:
                pattern = pattern_config.get('pattern', '')
                re.compile(pattern)
                console.print(f"[green]✓[/green] {name}")
            except re.error as e:
                console.print(f"[red]✗[/red] {name}: {e}")
                errors += 1
        
        # Validate API patterns
        console.print(f"\n[bold cyan]API Patterns Validation[/bold cyan]")
        for category, config in API_CONFIG.items():
            patterns = config.get('patterns', []) if isinstance(config, dict) else []
            for pattern in patterns:
                try:
                    re.compile(pattern)
                    console.print(f"[green]✓[/green] {category}: {pattern[:50]}...")
                except re.error as e:
                    console.print(f"[red]✗[/red] {category}: {pattern[:50]}... - {e}")
                    errors += 1
        
        # Validate JS patterns
        console.print(f"\n[bold cyan]JavaScript Patterns Validation[/bold cyan]")
        for category, config in JS_CONFIG.items():
            patterns = config.get('patterns', []) if isinstance(config, dict) else []
            for pattern in patterns:
                try:
                    re.compile(pattern)
                    console.print(f"[green]✓[/green] {category}: {pattern[:50]}...")
                except re.error as e:
                    console.print(f"[red]✗[/red] {category}: {pattern[:50]}... - {e}")
                    errors += 1
        
        if errors == 0:
            console.print(f"\n[bold green]All patterns are valid![/bold green]")
        else:
            console.print(f"\n[bold red]Found {errors} invalid pattern(s).[/bold red]")
        return
    
    if list_patterns:
        console.print(f"[bold blue]Secret Patterns ({len(SECRET_PATTERNS)})[/bold blue]")
        
        patterns_table = Table(show_header=True, header_style="bold magenta")
        patterns_table.add_column("Name", style="cyan", width=35)
        patterns_table.add_column("Confidence", style="yellow", width=10)
        patterns_table.add_column("Category", style="blue", width=15)
        patterns_table.add_column("Description", style="white")
        
        filtered_patterns = SECRET_PATTERNS
        if category:
            filtered_patterns = {k: v for k, v in SECRET_PATTERNS.items() 
                               if v.get('category', '').lower() == category.lower()}
        
        for name, config in filtered_patterns.items():
            confidence = config.get('confidence', 'medium')
            cat = config.get('category', 'generic')
            desc = config.get('desc', 'No description')
            patterns_table.add_row(name, confidence, cat, desc)
        
        console.print(patterns_table)
        return
    
    if list_api:
        console.print(f"[bold blue]API Endpoint Patterns ({len(API_CONFIG)})[/bold blue]")
        
        for category, config in API_CONFIG.items():
            if isinstance(config, dict):
                description = config.get('description', 'No description')
                patterns = config.get('patterns', [])
                
                console.print(f"\n[bold cyan]{category}[/bold cyan] - {description}")
                console.print(f"[dim]Patterns: {len(patterns)}[/dim]")
                
                for i, pattern in enumerate(patterns[:5], 1):  # Show first 5
                    console.print(f"  {i}. {pattern}")
                
                if len(patterns) > 5:
                    console.print(f"  ... and {len(patterns) - 5} more")
        return
    
    if list_js:
        console.print(f"[bold blue]JavaScript API Patterns ({len(JS_CONFIG)})[/bold blue]")
        
        for category, config in JS_CONFIG.items():
            if isinstance(config, dict):
                description = config.get('description', 'No description')
                patterns = config.get('patterns', [])
                
                console.print(f"\n[bold cyan]{category}[/bold cyan] - {description}")
                console.print(f"[dim]Patterns: {len(patterns)}[/dim]")
                
                for i, pattern in enumerate(patterns[:3], 1):  # Show first 3
                    console.print(f"  {i}. {pattern}")
                
                if len(patterns) > 3:
                    console.print(f"  ... and {len(patterns) - 3} more")
        return
    
    if show_stats:
        console.print(f"[bold blue]Pattern Statistics[/bold blue]")
        
        stats_table = Table(show_header=False, box=None)
        stats_table.add_column("Category", style="bold cyan")
        stats_table.add_column("Count", style="bold green")
        
        # Secret pattern stats
        stats_table.add_row("Secret Patterns", str(len(SECRET_PATTERNS)))
        
        # Count by confidence
        confidence_counts = {}
        for config in SECRET_PATTERNS.values():
            conf = config.get('confidence', 'medium')
            confidence_counts[conf] = confidence_counts.get(conf, 0) + 1
        
        for conf, count in confidence_counts.items():
            stats_table.add_row(f"  {conf.title()} Confidence", str(count))
        
        # API pattern stats
        stats_table.add_row("API Categories", str(len(API_CONFIG)))
        total_api_patterns = sum(len(config.get('patterns', [])) for config in API_CONFIG.values() if isinstance(config, dict))
        stats_table.add_row("Total API Patterns", str(total_api_patterns))
        
        # JS pattern stats
        stats_table.add_row("JS Categories", str(len(JS_CONFIG)))
        total_js_patterns = sum(len(config.get('patterns', [])) for config in JS_CONFIG.values() if isinstance(config, dict))
        stats_table.add_row("Total JS Patterns", str(total_js_patterns))
        
        console.print(stats_table)
        return
    
    console.print("Use --list, --list-api, --list-js, --stats, or --validate to view patterns.")

@app.command()
def init_patterns(
    secret_file: str = typer.Option("secret_patterns.json", "--secret-file", help="Secret patterns file to create."),
    api_file: str = typer.Option("api_patterns.json", "--api-file", help="API patterns file to create."),
    js_file: str = typer.Option("js_api_patterns.json", "--js-file", help="JS patterns file to create."),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite existing files.")
):
    """Initialize pattern files with default patterns."""
    
    files_to_create = [
        (secret_file, "secret patterns"),
        (api_file, "API patterns"),
        (js_file, "JavaScript patterns")
    ]
    
    for filename, description in files_to_create:
        file_path = Path(filename)
        
        if file_path.exists() and not overwrite:
            console.print(f"[yellow]{filename} already exists. Use --overwrite to replace it.[/yellow]")
            continue
        
        try:
            if filename == secret_file:
                default_content = {
                    "_metadata": {
                        "version": "1.0.0",
                        "description": "Default secret patterns for Web Recon Tool",
                        "total_patterns": 3
                    },
                    "AWS Access Key ID": {
                        "pattern": "(A[SK]IA[0-9A-Z]{16})",
                        "value_group": 1,
                        "desc": "Amazon Web Services Access Key ID.",
                        "confidence": "high",
                        "category": "cloud_services"
                    },
                    "GitHub Token": {
                        "pattern": "(ghp_[a-zA-Z0-9]{36})",
                        "value_group": 1,
                        "desc": "GitHub Personal Access Token.",
                        "confidence": "high",
                        "category": "version_control"
                    },
                    "Generic API Key": {
                        "pattern": "(['\"]?(?:api_?key|api_?token)['\"]?\\s*[:=]\\s*['\"]?\\s*([a-zA-Z0-9\\-_./+=]{20,128})\\s*['\"]?)",
                        "value_group": 2,
                        "desc": "Generic API key pattern.",
                        "confidence": "medium",
                        "min_entropy": 3.5,
                        "category": "generic"
                    }
                }
            elif filename == api_file:
                default_content = {
                    "_metadata": {
                        "version": "1.0.0",
                        "description": "Default API patterns for Web Recon Tool",
                        "total_categories": 3
                    },
                    "standard_api_paths": {
                        "description": "Common API endpoint patterns",
                        "patterns": ["/api", "/v[1-9]", "/rest", "/graphql"]
                    },
                    "admin_paths": {
                        "description": "Administrative interface endpoints",
                        "patterns": ["/admin", "/dashboard", "/panel"]
                    },
                    "auth_paths": {
                        "description": "Authentication endpoints",
                        "patterns": ["/auth", "/login", "/oauth", "/token"]
                    }
                }
            else:  # js_file
                default_content = {
                    "_metadata": {
                        "version": "1.0.0",
                        "description": "Default JavaScript API patterns for Web Recon Tool",
                        "total_categories": 3
                    },
                    "fetch_patterns": {
                        "description": "Native Fetch API patterns",
                        "patterns": ["fetch\\s*\\(\\s*['\"]([^'\"]+)['\"]"]
                    },
                    "axios_patterns": {
                        "description": "Axios HTTP client patterns",
                        "patterns": ["axios\\.\\w+\\s*\\(\\s*['\"]([^'\"]+)['\"]"]
                    },
                    "jquery_patterns": {
                        "description": "jQuery AJAX patterns",
                        "patterns": ["\\$\\.(?:ajax|get|post)\\s*\\([^)]*['\"]([^'\"]+)['\"]"]
                    }
                }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_content, f, indent=2, ensure_ascii=False)
            
            console.print(f"[bold green]Created {filename}[/bold green] - {description}")
            
        except IOError as e:
            console.print(f"[bold red]Error creating {filename}: {e}[/bold red]")
    
    console.print(f"\n[dim]Edit the files to add custom patterns and settings.[/dim]")

@app.callback()
def main(version: bool = typer.Option(None, "--version", "-v", is_eager=True, help="Show version and exit.")):
    if version:
        console.print(f"[bold green]{APP_NAME} version: {VERSION}[/bold green]")
        console.print("[dim]Modular reconnaissance with separate pattern files[/dim]")
        console.print(f"[dim]Pattern files: secret_patterns.json, api_patterns.json, js_api_patterns.json[/dim]")
        raise typer.Exit()

if __name__ == "__main__":
    app()