// Package isn implements the Ito-Saito-Nishizeki (ISN) secret sharing scheme
// for general monotone access structures.
//
// The ISN scheme generalises threshold secret sharing to arbitrary monotone
// access structures specified in either DNF (Disjunctive Normal Form) or CNF
// (Conjunctive Normal Form). Unlike Shamir's threshold scheme which only
// supports t-of-n access structures, ISN can handle complex authorization
// policies such as "any 2 executives OR any 3 managers" (DNF) or
// "at least one from each department" (CNF).
//
// # Share Representation
//
// Shares use a sparse map representation for space efficiency. Each share
// maps clause identifiers (represented as bitsets of party IDs) to group
// elements. The map only stores entries where the party holds a non-trivial
// piece; missing entries implicitly represent the group identity element.
//
// This sparse representation is particularly beneficial for large access
// structures where parties participate in only a fraction of the clauses.
//
// # DNF Variant
//
// The DNF scheme represents the access structure as minimal qualified sets
// (clauses). For each minimal qualified set B, the dealer creates an
// |B|-out-of-|B| additive sharing of the secret among the parties in B.
// Any authorized coalition contains at least one minimal qualified set
// and can therefore reconstruct the secret from that clause.
//
// Each party's share maps minimal qualified sets (as bitsets) to group
// elements. A party only has entries for minimal qualified sets they belong
// to, omitting clauses where they would hold the identity element.
//
// Example: Access structure "A = {p1,p2} OR {p2,p3,p4}" has two minimal
// qualified sets. Party p2 belongs to both sets and has 2 map entries,
// while parties p1, p3, p4 each belong to only one set and have 1 entry.
//
// # CNF Variant
//
// The CNF scheme represents the access structure as maximal unqualified sets
// (clauses). The dealer splits the secret into ℓ pieces (where ℓ is the
// number of maximal unqualified sets) and gives piece j to every party
// not in maximal unqualified set Tj. An authorized coalition is not
// contained in any maximal unqualified set, so it contains at least one
// party outside each Tj and can collect all pieces to reconstruct.
//
// Each party's share maps maximal unqualified sets (as bitsets) to group
// elements. A party only has entries for maximal unqualified sets they are
// NOT in (where they hold a secret piece), omitting clauses where they would
// hold the identity element.
//
// Example: Access structure "at least one from {p1,p2} AND at least one
// from {p3,p4}" has maximal unqualified sets {{p1,p2}, {p3,p4}}. Party p1
// is in {p1,p2} but not in {p3,p4}, so has 1 map entry for {p3,p4}.
//
// # Security
//
// The ISN scheme provides information-theoretic security: any unauthorised
// coalition learns no information about the secret. Unlike polynomial-based
// schemes (Shamir, Feldman, Pedersen), ISN works directly over any finite
// group without requiring field arithmetic.
//
// # Reference
//
// Section 4.2 of https://eprint.iacr.org/2025/518.pdf
package isn
