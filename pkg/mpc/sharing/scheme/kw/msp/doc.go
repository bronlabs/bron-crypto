// Package msp implements monotone span programmes (MSPs).
//
// An MSP is a linear-algebraic representation of a monotone access structure.
// It consists of a matrix M over a finite field, a target row vector t, and a
// labelling function that maps each row of M to a shareholder ID. A set of
// shareholders is qualified if and only if the target vector lies in the row
// span of their labelled rows.
//
// Key operations:
//   - [NewStandardMSP]: constructs an MSP with the standard target e_0 = (1,0,...,0)
//   - [NewMSP]: constructs an MSP with an explicit target vector
//   - [MSP.Accepts]: tests whether a set of IDs is qualified
//   - [MSP.ReconstructionVector]: computes the linear combination coefficients
//     that express the target as a combination of the selected rows
package msp
