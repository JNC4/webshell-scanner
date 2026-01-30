# Contributing to Webshell Scanner

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing.

## Ways to Contribute

- **Report bugs**: Open an issue describing the bug, steps to reproduce, and expected behavior
- **Suggest features**: Open an issue describing the feature and its use case
- **Add detection patterns**: Submit new webshell signatures or detection rules
- **Improve documentation**: Fix typos, clarify explanations, add examples
- **Submit code**: Fix bugs, implement features, improve performance

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/JNC4/webshell-scanner
   cd webshell-scanner
   ```

2. **Install Rust** (if not already installed)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

3. **Build and test**
   ```bash
   cargo build
   cargo test
   ```

## Submitting Changes

### Pull Request Process

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** with clear, descriptive commits
3. **Add tests** for new functionality
4. **Run the test suite** to ensure nothing is broken:
   ```bash
   cargo test
   cargo clippy --all-targets
   cargo fmt --check
   ```
5. **Update documentation** if needed (README, doc comments)
6. **Submit a pull request** with a clear description of changes

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Keep the first line under 72 characters
- Reference issues when relevant (`Fixes #123`)

### Code Style

- Follow Rust standard formatting (`cargo fmt`)
- No clippy warnings (`cargo clippy`)
- Add doc comments for public APIs
- Write tests for new functionality

## Adding Detection Patterns

When adding new webshell detection patterns:

1. **Research the pattern**: Understand the webshell technique being detected
2. **Write a precise regex**: Avoid overly broad patterns that cause false positives
3. **Choose the right category**:
   - `InputEvalChain`: User input flowing to code execution
   - `DecodeChain`: Obfuscated/encoded payloads
   - `KnownSignature`: Known webshell identifiers
   - `SuspiciousFunction`: Dangerous functions
   - `DynamicExecution`: Evasion techniques
4. **Add tests**: Include test cases in the appropriate test module
5. **Document**: Add a clear description for the pattern

Example:
```rust
CompiledPattern {
    regex: Regex::new(r#"(?i)new_webshell_signature"#).unwrap(),
    description: "Description of what this detects".to_string(),
    category: DetectionCategory::KnownSignature,
},
```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_name
```

### Test Coverage

When adding new features, please include:
- Unit tests for individual functions
- Integration tests for CLI behavior
- Test cases for both detection (true positives) and non-detection (true negatives)

## Reporting Security Issues

If you discover a security vulnerability, please **do not** open a public issue. Instead, report it privately by emailing the maintainers or using GitHub's private vulnerability reporting.

## Questions?

Feel free to open an issue for any questions about contributing.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
