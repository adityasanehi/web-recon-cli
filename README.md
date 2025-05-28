# Web Recon Tool (WRT)

**Version: 0.5.0** - Modular Pattern Configuration

Web Recon Tool (WRT) is a powerful Python command-line script designed for ethical security reconnaissance and debugging. It provides comprehensive web application analysis by scanning URLs, detecting API endpoints, and identifying potential secrets using configurable pattern files.

## 🚀 Key Features

### **Enhanced Secret Detection**
- **85+ Comprehensive Patterns**: Covers major cloud services, payment APIs, communication platforms, databases, and more
- **Confidence-Based Filtering**: High/Medium/Low confidence levels with entropy analysis
- **False Positive Reduction**: Advanced pattern matching with context analysis
- **Modular Pattern Files**: Easy-to-edit JSON configuration files

### **Advanced API Discovery** 
- **Categorized Endpoint Detection**: Authentication, Admin, Monitoring, Webhooks, Documentation
- **JavaScript Framework Support**: Fetch, Axios, jQuery, Angular, React patterns
- **Intelligent URL Validation**: Enhanced filtering and deduplication

### **Flexible Configuration**
- **Separate Pattern Files**: `secret_patterns.json`, `api_patterns.json`, `js_api_patterns.json`
- **Hot Reload**: Reload patterns without restarting
- **Pattern Validation**: Built-in validation and error checking
- **Community Friendly**: Easy JSON editing for contributions

### **Professional Output**
- **Rich Terminal Interface**: Colorful tables, progress bars, syntax highlighting
- **Categorized Results**: Organized by endpoint type and confidence level
- **Context Display**: Show surrounding code for better analysis
- **Export Options**: Save detailed reports to files

## 📁 Project Structure

```
webrecon/
├── webrecon.py              # Main reconnaissance tool
├── patterns/
│   ├── secret_patterns.json     # 85+ secret detection patterns
│   ├── api_patterns.json        # API endpoint patterns by category
│   ├── js_api_patterns.json     # JavaScript API call patterns
│   ├── custom_secrets.json      # Optional custom patterns
│   └── custom_apis.json         # Optional custom patterns
├── LICENSE
└── README.md
```

## 🛠 Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Quick Setup

1. **Clone or download the tool:**
   ```bash
   git clone <repository-url>
   cd web-recon-tool
   ```

2. **Create virtual environment (recommended):**
   ```bash
   python3 -m venv wrtenv
   source wrtenv/bin/activate  # On Windows: wrtenv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install typer rich requests beautifulsoup4 jsbeautifier
   ```

4. **Initialize pattern files (first run):**
   ```bash
   python webrecon.py init-patterns
   ```

## 🎯 Usage

### Basic Commands

**Scan a website:**
```bash
python webrecon.py scan https://example.com
```

**Advanced scanning:**
```bash
python webrecon.py scan https://example.com \
  --depth 2 \
  --min-confidence high \
  --show-context \
  --output report.txt
```

### Pattern Management

**View loaded patterns:**
```bash
python webrecon.py patterns --list           # Secret patterns
python webrecon.py patterns --list-api       # API patterns
python webrecon.py patterns --list-js        # JavaScript patterns
python webrecon.py patterns --stats          # Statistics
```

**Validate pattern files:**
```bash
python webrecon.py patterns --validate
```

**Initialize default patterns:**
```bash
python webrecon.py init-patterns --overwrite
```

### Command Reference

#### Scan Command
```bash
python webrecon.py scan [OPTIONS] TARGET_URL
```

**Options:**
- `--depth, -d INTEGER`: Crawling depth (0 = target only, default: 1)
- `--scan-js / --no-scan-js`: Include JavaScript analysis (default: enabled)
- `--scan-html / --no-scan-html`: Include HTML analysis (default: enabled)
- `--min-confidence [low|medium|high]`: Filter secrets by confidence (default: low)
- `--show-context / --no-context`: Show code context for secrets (default: disabled)
- `--categorize-apis / --no-categorize-apis`: Group API endpoints (default: enabled)
- `--reload-patterns`: Reload pattern files before scanning
- `--output, -o FILE`: Save results to file

#### Pattern Command
```bash
python webrecon.py patterns [OPTIONS]
```

**Options:**
- `--list, -l`: List secret patterns
- `--list-api`: List API endpoint patterns
- `--list-js`: List JavaScript patterns
- `--stats, -s`: Show pattern statistics
- `--validate, -v`: Validate all pattern files
- `--category, -c CATEGORY`: Filter by category

## 📊 Sample Output
![Demo](recon-demo.png)

## 🔧 Configuration

### Secret Patterns (`secret_patterns.json`)

Add new secret detection patterns:

```json
{
  "Custom API Key": {
    "pattern": "(customapi_[a-zA-Z0-9]{32})",
    "value_group": 1,
    "desc": "Custom service API key",
    "confidence": "high",
    "category": "custom_service"
  }
}
```

### API Patterns (`api_patterns.json`)

Define new endpoint categories:

```json
{
  "payment_endpoints": {
    "description": "Payment processing endpoints",
    "patterns": [
      "/payment(?:[/\\?#]|$)",
      "/billing(?:[/\\?#]|$)",
      "/checkout(?:[/\\?#]|$)"
    ]
  }
}
```

### JavaScript Patterns (`js_api_patterns.json`)

Add framework-specific API call patterns:

```json
{
  "vue_patterns": {
    "description": "Vue.js HTTP patterns",
    "patterns": [
      "this\\.$http\\.\\w+\\s*\\(\\s*['\"]([^'\"]+)['\"]"
    ]
  }
}
```

## 🔍 Detected Patterns

### Secret Categories
- **Cloud Services**: AWS, Google Cloud, Azure (12 patterns)
- **Version Control**: GitHub, GitLab, Bitbucket (6 patterns)
- **Communication**: Slack, Discord, Teams, Telegram (8 patterns)
- **Payment**: Stripe, PayPal, Square (6 patterns)
- **Databases**: MongoDB, Redis, PostgreSQL, MySQL (8 patterns)
- **Authentication**: JWT, SSH keys, OAuth tokens (7 patterns)
- **Development Tools**: Docker, NPM, PyPI (6 patterns)
- **Social Media**: Facebook, Twitter, YouTube (8 patterns)
- **Productivity**: Linear, Notion, Jira, Asana (8 patterns)
- **Infrastructure**: Twilio, SendGrid, Cloudflare (12 patterns)
- **Generic**: API keys, passwords, hex keys (4 patterns)

### API Endpoint Categories
- **Standard API Paths**: `/api`, `/v1`, `/rest`, `/graphql`
- **Admin Interfaces**: `/admin`, `/dashboard`, `/panel`
- **Authentication**: `/auth`, `/oauth`, `/login`, `/token`
- **File Operations**: `/upload`, `/download`, `/export`
- **Monitoring**: `/health`, `/status`, `/metrics`
- **Documentation**: `/docs`, `/swagger`, `/openapi`
- **Webhooks**: `/webhook`, `/callback`, `/notify`

## ⚠️ Ethical Use and Disclaimer

**🔴 FOR AUTHORIZED SECURITY TESTING ONLY 🔴**

This tool is designed for **legitimate security research, penetration testing, and debugging purposes**. You must have **explicit written permission** from system owners before scanning.

**⚠️ Important Warnings:**
- Unauthorized scanning is **illegal and unethical**
- Pattern-based detection can produce **false positives**
- Always **manually verify** potential secrets
- **Rate limiting** may occur with aggressive scanning
- Developers are **not responsible** for misuse

## 🤝 Contributing

We welcome contributions! The modular design makes it easy to add new patterns:

### Adding Secret Patterns
1. Edit `secret_patterns.json`
2. Add your pattern with proper metadata
3. Test with `python webrecon.py patterns --validate`
4. Submit a pull request

### Adding API Patterns
1. Edit `api_patterns.json` or `js_api_patterns.json`
2. Follow the existing structure
3. Validate your patterns
4. Submit with test cases

### Contribution Guidelines
- **Test thoroughly** to minimize false positives
- **Document patterns** with clear descriptions
- **Include metadata** (confidence, category, description)
- **Follow JSON formatting** standards

## 🐛 Known Limitations

- **Pattern-Based Detection**: May produce false positives/negatives
- **Static Analysis**: Limited to content available via HTTP requests
- **Dynamic Content**: JavaScript-rendered content may be missed
- **Rate Limiting**: Aggressive scanning may trigger protections
- **Encoding**: Assumes UTF-8 content encoding

## 📈 Recent Updates (v0.5.0)

- ✅ **Modular Pattern Files**: Separate JSON files for easy editing
- ✅ **85+ Secret Patterns**: Comprehensive coverage of modern services
- ✅ **Confidence Scoring**: High/Medium/Low classification
- ✅ **Enhanced Validation**: Built-in pattern validation
- ✅ **Hot Reload**: Reload patterns without restarting
- ✅ **Better Categorization**: Organized by service type
- ✅ **Improved CLI**: Enhanced commands and options

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details.

---

**Happy ethical hacking! 🔐✨**