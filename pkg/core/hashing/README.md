# HashAes: AES-based Hashing

HashAes implements an extension of the Tweakable Matyas-Meyer-Oseas (TMMO)
construction (Section 7.4 of [GKWY20](https://eprint.iacr.org/2019/074.pdf),
using a block cipher (π) as an ideal permutation. With an input `x` of size a
single block of π, and an index `i` ∈ [1,2,...,L] (for an output with L blocks
of π), the TMMO construction is defined as:

	digest[i] = TMMO^π (x,i) = π(π(x)⊕i)⊕π(x) 				∀i∈[L]

where π(x) is the block cipher (fixed-key AES, to leverage AES-NI instructions)
using as key the previous output of the TMMO output (the IV for the first block)
as prescribed by the Matyas-Meyer-Oseas construction. We use AES256 for π.

## Changes to the base algorithm
To allow variable-sized inputs, we:

A) Chain the output of the TMMOs to each input block by XORing the output of a
 block with the input of the next:

	x̂[0] = x[0]
	x̂[1] = x[1] ⊕ TMMO^π(x̂[0],idx)
	x̂[2] = x[2] ⊕ TMMO^π(x̂[1],idx) ...
	digest[i] = TMMO^π(x̂[L],idx)

B) Pad the last input block with zeros if it doesn't fit the AES block.

To allow compression of multiple inputs, we:

C) Chain the input of the first block to the output of the existing digest:

    x̂[0] = x[0] ⊕ digest[]

These changes apply the TMMO construction in chained mode, a semantic equivalent
to performing H(H(H(.....H(x)))), preserving the security of the scheme by strict
composition of one-way functions.

## Full algorithm
The full algorithm is described below:

```golang
1)  key = IV; π.key(IV)    // Initialise the cipher with the initialization vector (iv) as key.
                           // If no iv is provided, use the hardcoded IV.
2)  digest = [0,0,0,...,0] // Initialise the digest to lOut*B zeros
2A) x = padWithZeros(x)    // Pad with zeros so that len(x)%B == 0
3)  for i in {1...lOut/B}  // Loop over the output blocks, applying TMMO^π (x,i) at each iteration.
3B)     for j in {1...len(x)/B} // Loop over the input blocks...
            if j > 1            // ...chaining the TMMOs x̂[j] = x[j] ⊕ TMMO^π(x̂[j-1],i),i)
                x̂ = x[j] ^ digest[i] // C) This chaining also happens for j=0 if
            else                     // this algorithm is called more than once,
                x̂ = x[j]             // skipping step 2.
3.1)        // TMMO^π (x,idx) - Apply the TMMO to the current block.
3.1.1)      y = π.permute(x̂)        // π(x) - Apply the block cipher to the current block.
3.1.2)      y = y ⊕ (i*lOut/B+j)    // π(x)⊕idx - XOR the result of the permutation.
			                        // with the index. We combine the output block
                                    // index `i` (as defined in the TMMO) with the
                                    // input block index `j`.
3.1.3)      z = π.permute(y)        // π(π(x)⊕idx) - Apply the block cipher to the result of the XOR.]
3.1.4)      digest[i] = z ⊕ y       // π(π(x)⊕i)⊕π(x) - XOR the two permuted results.
3.2)    key = {key[1], digest[i]} // Set the current output block as the key for
        π.key(digest[i])          // the next iteration. Use half of the existing
                                  // key to cover the 2 blocks of the key (AES256)
```




