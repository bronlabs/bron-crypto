// Package cnf is a subpackage of isn that implements the CNF (Conjunctive Normal Form)
// variant of the Ito-Saito-Nishizeki secret sharing scheme.
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
package cnf
