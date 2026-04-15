# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security issues by emailing the maintainers directly at meatsquirk@gmail.com. Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability and determine severity
- **Fix Timeline**: Critical issues will be addressed within 7 days; others within 30 days
- **Disclosure**: We will coordinate disclosure timing with you

### Security Measures in This Library

This library implements several security measures:

#### Input Validation
- All filesystem paths are validated against directory traversal attacks
- Collection IDs and CIDs are sanitized before use
- Message sizes are bounded to prevent memory exhaustion

#### Cryptographic Security
- Ed25519 signatures use canonical CBOR encoding
- CID verification ensures content integrity
- No custom cryptographic implementations - uses audited libraries

#### Rate Limiting
- Configurable rate limiters for API endpoints
- Protection against denial of service

#### Fuzz Testing
- All parsing code is fuzz tested
- Targets include: message parsing, manifest parsing, framing, signatures

### Security Best Practices for Users

When using this library:

1. **Keep Dependencies Updated**: Regularly update to get security fixes
2. **Validate External Input**: Always validate data from untrusted sources
3. **Use Rate Limiting**: Enable rate limiting for public endpoints
4. **Monitor Logs**: Watch for suspicious patterns
5. **Secure Storage**: Protect the data directory with appropriate permissions

### Known Security Considerations

- **Bootstrap Nodes**: Verify bootstrap node authenticity in production deployments.
- **Private Keys**: Store Ed25519 private keys securely; never commit to version control.

## Security Audits

This library has not yet undergone a formal security audit. We welcome security researchers to review the code and report findings.

## Hall of Fame

We thank the following individuals for responsible disclosure:

- (Your name could be here!)
