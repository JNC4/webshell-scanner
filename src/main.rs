//! Webshell Scanner CLI
//!
//! A standalone tool for detecting webshells in PHP, JSP, ASP.NET, and Python files.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::Colorize;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use walkdir::WalkDir;

use webshell_scanner::{FrameworkDetector, ScanContext, WebshellScanner};

#[derive(Parser)]
#[command(name = "webshell-scanner")]
#[command(author = "REIUK LTD")]
#[command(version)]
#[command(about = "Detect webshells in PHP, JSP, ASP.NET, and Python files", long_about = None)]
struct Cli {
    /// Files or directories to scan
    #[arg(required_unless_present = "stdin")]
    paths: Vec<PathBuf>,

    /// Read content from stdin (use with --language)
    #[arg(long, conflicts_with = "paths")]
    stdin: bool,

    /// Language for stdin input
    #[arg(long, value_enum, requires = "stdin")]
    language: Option<Language>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Obfuscation threshold (default: 50)
    #[arg(short = 't', long, default_value = "50")]
    threshold: u32,

    /// Scan recursively
    #[arg(short, long)]
    recursive: bool,

    /// Enable context-aware scanning (reduces false positives)
    #[arg(short, long)]
    context_aware: bool,

    /// Show clean files in output
    #[arg(long)]
    show_clean: bool,

    /// Only show malicious files (exit code 1 if any found)
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Jsonl,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Language {
    Php,
    Jsp,
    Asp,
    Python,
}

impl From<Language> for webshell_scanner::WebshellLanguage {
    fn from(lang: Language) -> Self {
        match lang {
            Language::Php => webshell_scanner::WebshellLanguage::Php,
            Language::Jsp => webshell_scanner::WebshellLanguage::Jsp,
            Language::Asp => webshell_scanner::WebshellLanguage::AspNet,
            Language::Python => webshell_scanner::WebshellLanguage::Python,
        }
    }
}

#[derive(serde::Serialize)]
struct ScanOutput {
    path: String,
    is_malicious: bool,
    threat_level: String,
    language: Option<String>,
    obfuscation_score: u32,
    detections: Vec<DetectionOutput>,
}

#[derive(serde::Serialize)]
struct DetectionOutput {
    category: String,
    description: String,
    pattern: String,
    line: Option<usize>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let scanner = WebshellScanner::new(cli.threshold);
    let framework_detector = if cli.context_aware {
        Some(FrameworkDetector::new())
    } else {
        None
    };

    let mut results = Vec::new();
    let mut malicious_count = 0;

    if cli.stdin {
        // Read from stdin
        let mut content = String::new();
        io::stdin()
            .read_to_string(&mut content)
            .context("Failed to read from stdin")?;

        let result = if let Some(lang) = cli.language {
            scanner.scan_language(&content, lang.into())
        } else {
            scanner.scan(&content)
        };

        if result.is_malicious {
            malicious_count += 1;
        }

        let output = ScanOutput {
            path: "<stdin>".to_string(),
            is_malicious: result.is_malicious,
            threat_level: format!("{:?}", result.threat_level),
            language: result.language.map(|l| l.name().to_string()),
            obfuscation_score: result.obfuscation_score,
            detections: result
                .detections
                .into_iter()
                .map(|d| DetectionOutput {
                    category: d.category.name().to_string(),
                    description: d.description,
                    pattern: truncate_pattern(&d.pattern, 100),
                    line: d.line_number,
                })
                .collect(),
        };

        results.push(output);
    } else {
        // Scan files/directories
        for path in &cli.paths {
            if path.is_file() {
                if let Some(output) = scan_file(
                    &scanner,
                    path,
                    cli.context_aware,
                    framework_detector.as_ref(),
                )? {
                    if output.is_malicious {
                        malicious_count += 1;
                    }
                    if output.is_malicious || cli.show_clean {
                        results.push(output);
                    }
                }
            } else if path.is_dir() {
                let walker = if cli.recursive {
                    WalkDir::new(path)
                } else {
                    WalkDir::new(path).max_depth(1)
                };

                for entry in walker.into_iter().filter_map(|e| e.ok()) {
                    if entry.file_type().is_file() {
                        if let Some(output) = scan_file(
                            &scanner,
                            entry.path(),
                            cli.context_aware,
                            framework_detector.as_ref(),
                        )? {
                            if output.is_malicious {
                                malicious_count += 1;
                            }
                            if output.is_malicious || cli.show_clean {
                                results.push(output);
                            }
                        }
                    }
                }
            }
        }
    }

    // Output results
    if !cli.quiet {
        match cli.format {
            OutputFormat::Text => {
                for result in &results {
                    print_text_result(result);
                }

                // Summary
                eprintln!();
                if malicious_count > 0 {
                    eprintln!(
                        "{}",
                        format!("Found {} malicious file(s)", malicious_count)
                            .red()
                            .bold()
                    );
                } else {
                    eprintln!("{}", "No webshells detected".green());
                }
            }
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
            OutputFormat::Jsonl => {
                for result in &results {
                    println!("{}", serde_json::to_string(result)?);
                }
            }
        }
    }

    // Exit with error code if malicious files found
    if malicious_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn scan_file(
    scanner: &WebshellScanner,
    path: &std::path::Path,
    context_aware: bool,
    framework_detector: Option<&FrameworkDetector>,
) -> Result<Option<ScanOutput>> {
    // Check if we should scan this file
    if WebshellScanner::should_scan_language(path).is_none() {
        return Ok(None);
    }

    let content = fs::read_to_string(path).with_context(|| format!("Failed to read {:?}", path))?;

    let result = if context_aware {
        let context = ScanContext::from_path_with_detector(path, framework_detector);
        scanner.scan_with_context(&content, &context)
    } else if let Some(lang) = WebshellScanner::should_scan_language(path) {
        scanner.scan_language(&content, lang)
    } else {
        scanner.scan(&content)
    };

    Ok(Some(ScanOutput {
        path: path.display().to_string(),
        is_malicious: result.is_malicious,
        threat_level: format!("{:?}", result.threat_level),
        language: result.language.map(|l| l.name().to_string()),
        obfuscation_score: result.obfuscation_score,
        detections: result
            .detections
            .into_iter()
            .map(|d| DetectionOutput {
                category: d.category.name().to_string(),
                description: d.description,
                pattern: truncate_pattern(&d.pattern, 100),
                line: d.line_number,
            })
            .collect(),
    }))
}

fn print_text_result(result: &ScanOutput) {
    let status = match result.threat_level.as_str() {
        "Malicious" => "MALICIOUS".red().bold(),
        "Suspicious" => "SUSPICIOUS".yellow().bold(),
        _ => "CLEAN".green(),
    };

    println!("{} {}", status, result.path);

    if !result.detections.is_empty() {
        for detection in &result.detections {
            let line_info = detection
                .line
                .map(|l| format!(":{}", l))
                .unwrap_or_default();

            println!(
                "  {} [{}{}] {}",
                "→".dimmed(),
                detection.category.cyan(),
                line_info.dimmed(),
                detection.description
            );

            if !detection.pattern.is_empty() {
                println!("    {}", detection.pattern.dimmed());
            }
        }
    }

    if result.obfuscation_score > 0 {
        println!(
            "  {} Obfuscation score: {}",
            "→".dimmed(),
            result.obfuscation_score
        );
    }

    println!();
}

fn truncate_pattern(pattern: &str, max_len: usize) -> String {
    if pattern.len() > max_len {
        format!("{}...", &pattern[..max_len])
    } else {
        pattern.to_string()
    }
}
