# Nocopy

Types to prevent copying of structs after first use, useful for ensuring proper handling of sensitive data structures.

## Types

- **`NoCopy`** - Embed in structs to prevent copying (detected by `go vet`)
- **`CopyChecker`** - Runtime copy detection that panics if the struct has been copied

Use these types in cryptographic and security-sensitive code where copying could lead to bugs or security issues.
