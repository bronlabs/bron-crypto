// Package dnf is a subpackage of isn that implements the DNF (Disjunctive Normal Form)
// variant of the Ito-Saito-Nishizeki secret sharing scheme.
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
package dnf
