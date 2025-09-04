# End-of-Life Packages

This pattern detects packages that have already reached their end-of-life (EOL) date, meaning they are no longer maintained, supported, or receiving security updates from their vendors or maintainers.

## Why this is important

Using end-of-life software poses significant security risks:

- **No security updates**: EOL packages won't receive patches for newly discovered vulnerabilities
- **No bug fixes**: Issues in EOL packages will remain unresolved
- **Compliance violations**: Many security frameworks require avoiding EOL software
- **Technical debt**: EOL packages may become incompatible with newer systems

## How to fix

1. **Update to a supported version**: Check if a newer, maintained version of the package is available
2. **Find alternatives**: If the package is completely discontinued, migrate to an actively maintained alternative
3. **Vendor support**: Contact the vendor to understand extended support options (if available)
4. **Risk assessment**: If immediate replacement isn't possible, document the risk and create a migration plan

## Example

```json
{
  "dependencies": {
    "some-eol-package": "1.0.0"  // This version reached EOL on 2023-01-01
  }
}
```

## References

- [NIST Guidelines on Software End-of-Life](https://csrc.nist.gov/projects/software-identification-tagging)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
