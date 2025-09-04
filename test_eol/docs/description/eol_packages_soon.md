# Soon-to-be End-of-Life Packages

This pattern detects packages that are approaching their end-of-life (EOL) date within the next 6 months. These packages will soon stop receiving maintenance, support, and security updates.

## Why this is important

Planning ahead for EOL packages helps:

- **Proactive security management**: Avoid last-minute scrambles to replace critical dependencies
- **Budget planning**: Allocate resources for migration or extended support
- **Risk mitigation**: Reduce the window of vulnerability exposure
- **Compliance preparation**: Meet security framework requirements before deadlines

## How to fix

1. **Plan migration**: Create a timeline to update or replace the package before its EOL date
2. **Evaluate alternatives**: Research maintained alternatives or newer versions
3. **Test compatibility**: Ensure replacement packages work with your existing codebase
4. **Extended support**: Investigate if commercial extended support is available and cost-effective
5. **Risk documentation**: Document the timeline and migration plan for stakeholders

## Example

```json
{
  "dependencies": {
    "legacy-package": "2.1.0"  // This version will reach EOL on 2024-08-15
  }
}
```

## Best practices

- Monitor EOL announcements from package maintainers
- Set up automated alerts for approaching EOL dates
- Maintain an inventory of all dependencies and their EOL schedules
- Prioritize migration based on package criticality and exposure

## References

- [Software End-of-Life Planning Guide](https://www.cisa.gov/sites/default/files/publications/Software_End_of_Life_Planning_Guide.pdf)
- [Dependency Management Best Practices](https://owasp.org/www-project-dependency-track/)
