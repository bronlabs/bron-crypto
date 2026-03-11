// Package accessstructures defines interfaces and dispatch logic for monotone
// access structures used in secret sharing.
//
// An access structure specifies which subsets of shareholders are authorized
// to reconstruct a shared secret. This package provides two interface levels:
//   - [Monotone]: base interface for any monotone access structure
//   - [Linear]: extends Monotone with enumeration of maximal unqualified sets,
//     enabling MSP (Monotone Span Programme) induction
//
// Concrete implementations live in sub-packages:
//   - [threshold]: classic (t,n) threshold access structures
//   - [unanimity]: n-of-n access structures (all shareholders required)
//   - [cnf]: access structures in conjunctive normal form
//   - [hierarchical]: hierarchical conjunctive threshold access structures
//   - [boolexpr]: access structures defined by threshold/and/or gate access trees
//
// The [InducedMSP] function dispatches to the appropriate MSP construction for
// any Linear access structure.
package accessstructures
