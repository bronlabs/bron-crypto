# Sigma Protocol Compilers

Compilers that transform interactive sigma protocols into non-interactive zero-knowledge proofs of knowledge (NIZKPoK).

## Supported Compilers

| Compiler | Security | Use Case |
| ---------- | ---------- | ---------- |
| `fiatshamir` | Sequential | Simple, efficient proofs |
| `fischlin` | UC-secure | Composable protocols |
| `randfischlin` | UC-secure | OR composition support |

## Usage

```go
import "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"

// Compile a sigma protocol
nizk, err := compiler.Compile(fiatshamir.Name, sigmaProtocol, prng)

// Create prover and verifier
prover, _ := nizk.NewProver(ctx)
verifier, _ := nizk.NewVerifier(ctx)

// Generate and verify proof
proof, _ := prover.Prove(statement, witness)
err = verifier.Verify(statement, proof)
```

## Subpackages

- `fiatshamir/` - Fiat-Shamir transform
- `fischlin/` - Fischlin transform with dynamic parameters
- `randfischlin/` - Randomised Fischlin with fixed parameters
- `zk/` - Interactive 5-round ZK protocol from any sigma protocol
