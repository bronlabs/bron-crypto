// Package gennaro implements Gennaro-style distributed key generation over
// arbitrary monotone access structures via MSP-based Feldman/Pedersen sharing.
//
// Each party deals a Pedersen sharing, parties verify and accept contributions,
// then convert the joint Pedersen sharing into a final Feldman shard tied to
// the MSP induced from the supplied access structure.
//
// See README.md for protocol details and usage guidance.
package gennaro
