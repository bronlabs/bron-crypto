// Package boolexpr implements monotone access structures given by threshold
// gates over shareholder attributes.
//
// The package represents an access structure as a rooted tree whose internal
// nodes are threshold gates and whose leaves are shareholder IDs. This covers
// threshold formulas, as well as AND/OR formulas as special cases.
//
// MSP induction is implemented by [InducedMSP], which follows the threshold-gate
// tree conversion of Liu, Cao, and Wong, "Efficient Generation of Linear Secret
// Sharing Scheme Matrices from Threshold Access Trees" (ePrint 2010/374). The
// induced MSP has one row per attribute leaf.
package boolexpr
