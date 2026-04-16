# Monotone Span Programme (MSP)

Implements monotone span programmes, the linear-algebraic representation of monotone access structures.

## Overview

An MSP consists of:

- A matrix **M** over a finite field
- A target row vector **t**
- A labelling function mapping each row of **M** to a shareholder ID

A set of shareholders is **qualified** if and only if the target vector lies in the row span of their labelled rows.

## Usage

```go
// Construct an MSP with the standard target e_0 = (1,0,...,0)
mspProgram, err := msp.NewMSP(matrix, rowsToHolders)

// Test qualification
qualified := mspProgram.Accepts(id1, id2, id3)

// Get reconstruction coefficients
reconVector, err := mspProgram.ReconstructionVector(id1, id2, id3)
```

## Properties

- **Ideal MSP**: exactly one row per shareholder (`IsIdeal()`)
- **Size**: number of rows in the matrix (`Size()`)
- **D**: number of columns in the matrix (`D()`)
