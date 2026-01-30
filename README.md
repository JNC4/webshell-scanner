# Webshell Scanner

A standalone, open-source webshell detection tool supporting PHP, JSP, ASP.NET, and Python.

Extracted from [XPAV](https://github.com/JNC4/xpav) to be a focused, single-purpose tool.

## Features

- **Multi-language support**: PHP, JSP, ASP.NET, Python (20+ file extensions)
- **Multiple detection methods**:
  - Input-to-eval chains (user input → code execution)
  - Decode chains (base64, gzinflate, rot13 obfuscation)
  - Known signatures (c99, r57, b374k, WSO, China Chopper, Weevely)
  - Suspicious function detection
  - Dynamic execution patterns
  - Obfuscation scoring
- **Context-aware scanning**: Reduces false positives in frameworks (WordPress, Laravel, Symfony, Drupal) and vendor directories
- **Multiple output formats**: Text, JSON, JSONL
- **Library + CLI**: Use as a Rust library or command-line tool

## Installation

### From source

```bash
git clone https://github.com/JNC4/webshell-scanner
cd webshell-scanner
cargo install --path .
```

### As a library

```toml
[dependencies]
webshell-scanner = "0.1"
```

## Usage

### CLI

```bash
# Scan a single file
webshell-scanner suspicious.php

# Scan a directory recursively
webshell-scanner -r /var/www/html

# Scan with context-awareness (reduces false positives)
webshell-scanner -r -c /var/www/wordpress

# Output as JSON
webshell-scanner -f json /var/www/html

# Pipe content via stdin
cat suspicious.php | webshell-scanner --stdin --language php

# Quiet mode (exit code 1 if malicious found)
webshell-scanner -q /var/www/html && echo "Clean" || echo "Infected"
```

### Options

```
Usage: webshell-scanner [OPTIONS] [PATHS]...

Arguments:
  [PATHS]...  Files or directories to scan

Options:
  -f, --format <FORMAT>      Output format [default: text] [possible values: text, json, jsonl]
  -t, --threshold <THRESHOLD>  Obfuscation threshold [default: 50]
  -r, --recursive            Scan recursively
  -c, --context-aware        Enable context-aware scanning (reduces false positives)
      --show-clean           Show clean files in output
  -q, --quiet                Only show malicious files (exit code 1 if any found)
      --stdin                Read content from stdin (use with --language)
      --language <LANGUAGE>  Language for stdin input [possible values: php, jsp, asp, python]
  -h, --help                 Print help
  -V, --version              Print version
```

### Library

```rust
use webshell_scanner::{WebshellScanner, ThreatLevel, ScanContext};

// Create scanner with obfuscation threshold
let scanner = WebshellScanner::new(50);

// Basic scan
let result = scanner.scan(r#"<?php eval($_GET['cmd']); ?>"#);
assert!(result.is_malicious);
assert_eq!(result.threat_level, ThreatLevel::Malicious);

// Language-specific scan
let result = scanner.scan_jsp(r#"<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>"#);
assert!(result.is_malicious);

// Context-aware scan (reduces false positives in frameworks)
let context = ScanContext::from_path(std::path::Path::new("/var/www/vendor/lib.php"));
let result = scanner.scan_with_context(content, &context);
```

## Detection Categories

| Category | Description |
|----------|-------------|
| **InputEvalChain** | User input (`$_GET`, `$_POST`, etc.) flowing to code execution |
| **DecodeChain** | Obfuscated payloads (base64 → eval, gzinflate chains) |
| **KnownSignature** | Known webshell signatures (c99, r57, b374k, WSO, etc.) |
| **SuspiciousFunction** | Dangerous functions without direct user input chain |
| **DynamicExecution** | Evasion via string concatenation, variable variables, chr() chains |
| **Obfuscation** | High obfuscation score indicating packed/encoded code |

## Supported File Extensions

### PHP
`.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.phar`, `.inc`

### JSP
`.jsp`, `.jspx`, `.jspa`, `.jsw`, `.jsv`

### ASP.NET
`.aspx`, `.ashx`, `.asmx`, `.ascx`, `.asp`

### Python
`.py`, `.pyw`

## Context-Aware Scanning

When enabled (`-c` flag), the scanner automatically:

1. **Detects frameworks**: WordPress, Laravel, Symfony, Drupal, Composer
2. **Adjusts thresholds** for vendor directories (`/vendor/`, `/node_modules/`)
3. **Handles cache directories** with higher thresholds
4. **Recognizes minified code** to avoid false positives

## Exit Codes

- `0`: No malicious files found
- `1`: One or more malicious files detected

## Contributing

Contributions welcome. Please open an issue or PR on GitHub.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Credits

Originally developed as part of [XPAV](https://github.com/reiuk/xpav) by REIUK LTD.
