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

A) Pad the last input block with zeros if it doesn't fit the AES block.

A) Chain the output of the TMMOs to each input block by setting the key:

	π.key = IV
	digest[idx] = TMMO^π(x̂[0],idx)
	π.key = {digest[idx], π.key[0] ⊕ π.key[1]}
    idx++
	digest[idx] = TMMO^π(x̂[1],idx) ...

These changes apply the TMMO construction in chained mode following the 
Matyas-Meyer-Oseas composition, thus preserving the security of the scheme by 
strict composition of one-way functions.

## Full algorithm
The full algorithm is described below:

```golang
1)  key = IV; π.setKey(IV) // Initialise the cipher with the initialization vector (iv) as key.
                           // If no iv is provided, use the hardcoded IV.
2)  digest = [0,0,0,...,0] // Initialise the digest to lOut*B zeros
2A) x = padWithZeros(x)    // Pad with zeros so that len(x)%B == 0
3)  for i in {1...lOut/B}  // Loop over the output blocks,
3.B)    for j in {1...len(x)/B} // Loop over the input blocks,
3.1)                                  // TMMO^π (x,idx) - Apply the TMMO to the current block.
3.1.1)      y = π.permute(x̂)          // π(x) - Apply the block cipher as a random permutation.
3.1.2)      y = y ⊕ (idx)             // π(x)⊕idx - XOR the result of the permutation.
			                          // with the index. We use a counter of TMMOs as index.
3.1.3)      z = π.permute(y)          // π(π(x)⊕idx) - Apply the block cipher to the result of the XOR.
3.1.4)      digest[i] = z ⊕ y         // π(π(x)⊕i)⊕π(x) - XOR the two permuted results.
3.1.B)      key = {digest[i], key[0]⊕key[1]} // Refresh the AES256 cipher key for the next iteration. 
			π.setKey(key)             // Fill the  first half of the key with the output block (following 
			                          // the Matyas-Meyer-Oseas construction). Use a permutation on the 
			                          // existing key (key[0] ⊕ key[1]) to cover the second block 
                                      // of the key (AES256)
```




