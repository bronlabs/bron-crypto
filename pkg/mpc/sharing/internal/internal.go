package internal

// ID uniquely identifies a shareholder. IDs must be non-zero for polynomial-based schemes
// since they serve as evaluation points.
type ID uint64
