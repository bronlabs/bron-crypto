// Package unanimity implements n-of-n access structures.
//
// In a unanimity access structure every shareholder must participate to
// reconstruct the secret. This is the access structure underlying additive
// secret sharing. A set is qualified if and only if it equals the full
// shareholder set.
//
// MSP induction converts the unanimity structure to CNF form (n singleton
// clauses) and builds the MSP from that representation.
package unanimity
