// Package cnf implements monotone access structures in conjunctive normal form.
//
// A CNF access structure is specified by its maximal unqualified sets
// {T_1, ..., T_l}. A coalition is authorized if and only if it is not a
// subset of any T_j. Equivalently, each clause C_j = P \ T_j must contain
// at least one member of the coalition.
//
// CNF is the canonical target representation for MSP induction of arbitrary
// linear access structures: [ConvertToCNF] materialises any [Linear] access
// structure into CNF, and [InducedMSP] builds the corresponding monotone
// span programme.
package cnf
