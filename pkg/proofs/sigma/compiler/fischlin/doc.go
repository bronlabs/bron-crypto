// Package fischlin implements the Fischlin transform for compiling interactive
// sigma protocols into non-interactive zero-knowledge proofs with UC security.
//
// Fischlin's transform provides universally composable (UC) security, which is
// stronger than the standard Fiat-Shamir transform. It achieves this by requiring
// the prover to find challenge/response pairs that hash to zero.
//
// The parameters rho (number of repetitions), b (hash output bits), and t (search
// bound) are computed based on the sigma protocol's special soundness property to
// achieve a target soundness error of 2^(-128).
//
// Reference: "Optimising and Implementing Fischlin's Transform for UC-Secure
// Zero-Knowledge" by Chen & Lindell.
package fischlin
