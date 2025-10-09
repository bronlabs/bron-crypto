# dudect - Statistical Constant-Time Analysis for Go

This package implements the dudect statistical timing analysis approach for detecting timing leaks in cryptographic implementations.

## Features

- Statistical t-test based timing analysis
- Percentile-based cropping for handling outliers
- Automatic parameter tuning (Inner iterations)
- Early stopping when leaks are clearly detected or absent
- Preflight checks for environment validation
- Support for both constant-time and variable-time detection

## Usage

```go
import "github.com/bronlabs/bron-crypto/tools/dudect"

// Define your test function
build := func(cls byte, i int, rng *dudect.Rand) func() {
    // cls == 0: one input class (e.g., zeros)
    // cls == 1: another input class (e.g., ones)
    input := generateInput(cls)
    return func() {
        // Operation to test
        cryptoOperation(input)
    }
}

// Configure analysis
cfg := dudect.Config{
    Target:            "My Crypto Operation",
    NMeasures:         10000,
    TargetNsPerSample: 5000,
    EarlyStop:         true,
}

// Run preflight checks (optional but recommended)
report, tunedCfg := dudect.Preflight(build, cfg)
fmt.Println(report)

// Run analysis
result := dudect.Run(build, tunedCfg)

if result.Leak {
    fmt.Printf("Timing leak detected: max|t|=%.2f\n", result.MaxT)
} else {
    fmt.Printf("No timing leak: max|t|=%.2f\n", result.MaxT)
}
```

## Configuration

- `NMeasures`: Number of timing measurements to collect
- `TargetNsPerSample`: Target nanoseconds per sample (for auto-tuning)
- `Inner`: Number of inner iterations per measurement
- `TThreshold`: t-statistic threshold for leak detection (default: 4.5)
- `NumPercentiles`: Number of percentile crops (default: 15)
- `EarlyStop`: Enable early stopping when threshold is clearly exceeded

## Interpretation

- `max|t| < 4.5`: Likely constant-time
- `max|t| > 4.5`: Timing leak detected
- Higher t-values indicate stronger timing dependencies

## Example: Testing Paillier Encryption

See `example_test.go` for complete examples testing Paillier encryption operations.

## References

- Original dudect: https://github.com/oreparaz/dudect
- Paper: "Dude, is my code constant time?" by Reparaz et al.