## README.md

# Web Recon Tool (WRT)

**Version: 0.2.1**

Web Recon Tool (WRT) is a Python command-line script designed for debugging and white-hat security reconnaissance. It takes a URL as input, fetches its content, and recursively (up to a specified depth) scans linked HTML pages and JavaScript files to identify:

* Discovered URLs
* Potential API/Backend Endpoints
* Potential Secrets (API keys, tokens, sensitive keywords)

The tool aims to provide a clean, colorful, and well-organized output in the terminal using the `rich` library and a structured CLI interface via `typer`.

## Features

* **URL Discovery:** Finds absolute and relative URLs in HTML (attributes like `href`, `src`) and JavaScript code.
* **API Endpoint Identification:** Uses a list of common patterns and keywords (e.g., `/api/`, `/v1/`, `graphql`) to flag potential API endpoints. Also looks for URLs in common JS API call patterns (`fetch`, `axios`, etc.).
* **Secret Scanning:** Employs regular expressions to search for common secret patterns like API keys (AWS, Google, GitHub, Stripe, etc.), authorization tokens, JWTs, private key markers, and connection strings. Includes basic false positive reduction.
* **Recursive Scanning:** Can crawl linked pages up to a user-defined depth.
* **JavaScript Analysis:** Fetches and scans external JavaScript files and inline scripts. Uses `jsbeautifier` to format JS for potentially more reliable regex matching.
* **User-Friendly CLI:** Powered by `Typer` for easy argument parsing and help messages.
* **Rich Output:** Utilizes `Rich` for formatted tables, syntax-highlighted code contexts for secrets, and progress bars.
* **Output to File:** Option to save the scan results to a text file.
* **Context for Secrets:** Optionally displays a few lines of code surrounding a found secret for better context.

## Ethical Use and Disclaimer

⚠️ **WARNING: FOR ETHICAL AND LEGAL USE ONLY** ⚠️

This tool is intended for **legitimate debugging, security research, and white-hat penetration testing purposes only**. You must have **explicit, written permission** from the owner of any system or website before scanning it with this tool.

Unauthorized scanning or use of this tool against systems you do not have permission to test is **illegal and unethical**. The developers of this tool are not responsible for any misuse or damage caused by this script.

**Secret detection is based on patterns and regular expressions, which can lead to false positives.** Always manually verify any potential secrets found. Do not assume that everything flagged as a secret is indeed sensitive or exploitable without further investigation.

## Installation

1.  **Prerequisites:**
    * Python 3.7+

2.  **Clone the repository or save the script:**
    If you have it as a standalone `webrecon.py` file, you can skip this.

3.  **Install dependencies:**
    It's highly recommended to use a virtual environment.

    ```bash
    python3 -m venv wrtenv
    source wrtenv/bin/activate  # On Windows: wrtenv\Scripts\activate
    pip install typer rich requests beautifulsoup4 jsbeautifier
    ```

4.  **Make the script executable (Optional):**
    ```bash
    chmod +x webrecon.py
    ```

## Usage

```bash
python webrecon.py scan [OPTIONS] TARGET_URL
```

Or if executable:

```bash
./webrecon.py scan [OPTIONS] TARGET_URL
```

**Arguments:**

* `TARGET_URL`: The base URL to start scanning from (Required).

**Options:**

* `--depth, -d INTEGER`: Crawling depth for linked pages. `0` means only the target URL. Default: `1`.
* `--scan-js / --no-scan-js`: Scan linked JavaScript files. Default: `True`.
* `--scan-html / --no-scan-html`: Scan inline HTML content for secrets/URLs beyond just tags. Default: `True`.
* `--show-context / --no-context`: Show code context for found secrets. Default: `False`.
* `--output, -o FILENAME`: Save results to a file (e.g., `results.txt`).
* `--version, -v`: Show script version and exit.
* `--help`: Show help message and exit.

**Examples:**

1.  **Scan a single URL with default depth (1), including JS and HTML analysis:**
    ```bash
    python webrecon.py scan [https://example.com](https://example.com)
    ```

2.  **Scan only the target URL (depth 0) and don't scan JavaScript files:**
    ```bash
    python webrecon.py scan [https://example.com](https://example.com) --depth 0 --no-scan-js
    ```

3.  **Scan with a depth of 2 and show context for secrets:**
    ```bash
    python webrecon.py scan [https://another-example.com](https://another-example.com) --depth 2 --show-context
    ```

4.  **Save the output to a file:**
    ```bash
    python webrecon.py scan [https://testsite.org](https://testsite.org) -o report.txt
    ```

## Output

The tool will display:

1.  **Discovered URLs:** A table of all unique URLs found.
2.  **Potential API/Backend Endpoints:** A table of URLs that match common API patterns.
3.  **Potential Secrets Found:** A table listing the type of secret, its excerpt, and the source file/URL. If `--show-context` is used, relevant code snippets will be displayed.

## Known Limitations

* **False Positives/Negatives:** Secret and API endpoint detection relies on regex and heuristics, which means it can produce false positives (flagging something that isn't a secret/API) or false negatives (missing actual secrets/APIs). **Manual verification is crucial.**
* **Dynamic Content:** The tool primarily analyzes static content fetched via HTTP requests. Websites that heavily rely on client-side JavaScript to render content or fetch further data dynamically might not reveal all their URLs or secrets through this method alone. More advanced tools like headless browsers (e.g., Selenium, Playwright) might be needed for such cases.
* **Scope of Regexes:** While the regex patterns cover many common cases, they are not exhaustive and might miss novel or custom secret formats.
* **Rate Limiting/Blocking:** Aggressive scanning (especially with greater depth) can lead to your IP being rate-limited or blocked by the target server or WAF. Use responsibly.
* **Character Encoding:** Assumes UTF-8 for decoding content. Other encodings might lead to parsing issues.

## Contributing (Example Section)

Contributions are welcome! If you have ideas for improvements, new secret patterns, or bug fixes, please consider:

1.  Forking the repository (if applicable).
2.  Creating a new branch for your feature or fix.
3.  Submitting a pull request with a clear description of your changes.

Please ensure any new secret patterns are well-tested to minimize false positives.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details (or you can add an MIT License file if you distribute this).
```

**To use this README:**

1.  Save the content above into a file named `README.md` in the same directory as your `webrecon.py` script.
2.  If you're using Git, add and commit it to your repository.

This provides a good starting point for your tool's documentation. Remember to update it as you add more features or make significant changes.