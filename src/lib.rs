//! Webshell Scanner Library
//!
//! A standalone library for detecting webshells via pattern matching and obfuscation scoring.
//!
//! ## Supported Languages
//!
//! - **PHP**: `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.phar`, `.inc`
//! - **JSP**: `.jsp`, `.jspx`, `.jspa`, `.jsw`, `.jsv`
//! - **ASP.NET**: `.aspx`, `.ashx`, `.asmx`, `.ascx`, `.asp`
//! - **Python**: `.py`, `.pyw`
//!
//! ## Detection Methods
//!
//! 1. **Input-to-Eval Chains**: User input flowing directly to code execution
//! 2. **Decode Chains**: Obfuscated code execution (base64, gzinflate, etc.)
//! 3. **Known Signatures**: c99, r57, b374k, WSO, China Chopper, etc.
//! 4. **Suspicious Functions**: eval, system, exec, shell_exec, etc.
//! 5. **Dynamic Execution**: String concatenation, variable variables, chr() chains
//! 6. **Obfuscation Scoring**: Quantifies code obfuscation level
//!
//! ## Example
//!
//! ```rust
//! use webshell_scanner::{WebshellScanner, ThreatLevel};
//!
//! let scanner = WebshellScanner::new(50);
//! let result = scanner.scan(r#"<?php eval($_GET['cmd']); ?>"#);
//!
//! assert!(result.is_malicious);
//! assert_eq!(result.threat_level, ThreatLevel::Malicious);
//! ```

mod framework;
mod scanner;

pub use framework::{Framework, FrameworkDetector};
pub use scanner::{
    is_likely_minified, Detection, DetectionCategory, ScanContext, ThreatLevel, WebshellLanguage,
    WebshellScanResult, WebshellScanner,
};
