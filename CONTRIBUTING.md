# Contributing to DCPP Wire Protocol

Thank you for your interest in contributing to the DCPP Wire Protocol library!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/dcpp-wire-protocol` (replace `<your-username>` with your GitHub username)
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run tests: `cargo test --features full`
6. Submit a pull request
7. Read the RFC!

## Development Setup

### Prerequisites

- Rust 1.70 or higher
- OpenSSL development headers
- Protobuf compiler (for libp2p features)

### Building

```bash
# Build core library
cargo build

# Build with all features
cargo build --features full

# Run tests
cargo test --features full

# Run clippy lints
cargo clippy --features full -- -D warnings

# Format code
cargo fmt
```

## Code Guidelines

### Rust Style

- Follow standard Rust formatting (`cargo fmt`)
- Use `cargo clippy` and fix all warnings
- Add documentation comments for public APIs
- Use meaningful variable and function names

### Documentation

- All public items should have doc comments
- Include examples in doc comments where helpful
- Update README.md if adding new features

### Testing

- Add unit tests for new functionality
- Add integration tests for complex features
- Ensure all tests pass before submitting PR
- Run fuzz tests for parsing code: `cargo +nightly fuzz run <target>`

### Commit Messages

Use clear, descriptive commit messages:

```
Add rate limiting module for API protection

- Implement sliding window rate limiter
- Add tiered rate limiting for different endpoints
- Include comprehensive test coverage
```

## Pull Request Process

1. **Update documentation** - Update README.md and doc comments as needed
2. **Add tests** - Include tests for new functionality
3. **Run CI checks** - Ensure `cargo test`, `cargo clippy`, and `cargo fmt` pass
4. **Describe changes** - Provide a clear description in the PR
5. **Link issues** - Reference any related issues

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe tests added or modified

## Checklist
- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No new warnings from clippy
```

## Reporting Issues

### Bug Reports

Include:
- Rust version (`rustc --version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant error messages or logs

### Feature Requests

Include:
- Use case description
- Proposed API or interface
- Any relevant protocol considerations

## Security Issues

For security vulnerabilities, please do NOT open a public issue. Instead, report privately to the maintainers.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Open a discussion or issue if you have questions about contributing.
