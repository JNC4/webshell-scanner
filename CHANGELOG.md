# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-30

### Added

- Initial release as standalone tool (extracted from [XPAV](https://github.com/JNC4/xpav))
- **Multi-language support**: PHP, JSP, ASP.NET, Python
- **Detection methods**:
  - Input-to-eval chain detection (user input flowing to code execution)
  - Decode chain detection (base64, gzinflate, rot13 obfuscation)
  - Known webshell signatures (c99, r57, b374k, WSO, China Chopper, Weevely)
  - Suspicious function detection
  - Dynamic execution pattern detection
  - Obfuscation scoring
- **Context-aware scanning**: Framework detection (WordPress, Laravel, Symfony, Drupal) to reduce false positives
- **Multiple output formats**: Text (colored), JSON, JSONL
- **CLI features**:
  - Recursive directory scanning
  - Stdin input support
  - Quiet mode with exit codes
  - Configurable obfuscation threshold
- **Library API**: Use as a Rust crate in your own projects

### Supported File Extensions

- PHP: `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.phar`, `.inc`
- JSP: `.jsp`, `.jspx`, `.jspa`, `.jsw`, `.jsv`
- ASP.NET: `.aspx`, `.ashx`, `.asmx`, `.ascx`, `.asp`
- Python: `.py`, `.pyw`

[Unreleased]: https://github.com/JNC4/webshell-scanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/JNC4/webshell-scanner/releases/tag/v0.1.0
