// Package kw implements the Karchmer-Wigderson monotone span programme (MSP)
// based secret sharing scheme.
//
// Unlike Shamir's scheme, which is restricted to threshold access structures,
// the KW scheme realises any monotone access structure that can be expressed
// as a linear access structure (i.e. one that admits an MSP). This includes
// threshold, unanimity, CNF, and hierarchical conjunctive structures.
//
// Dealing builds the MSP M from the access structure, samples a random column
// vector r with r[0] = secret, and computes the share vector lambda = M * r.
// Each shareholder receives the rows of lambda corresponding to their MSP rows.
//
// Reconstruction finds linear recombination coefficients c such that
// c^T * M_I = target, then recovers the secret as c . lambda_I (dot product).
// The scheme is linearly homomorphic: share addition and scalar multiplication
// carry through to the reconstructed secret.
package kw
