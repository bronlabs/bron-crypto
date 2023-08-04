# Realization of DKLs23 RVOLE functionality

This package implements the two-party OT-based multiplication protocol that is used inside [DKLs23](https://eprint.iacr.org/2023/765.pdf), originating from [DKLs19](https://eprint.iacr.org/2019/523.pdf). This protocol is realization of DKLs23 F_RVOLE functionality accepting two commands: Sampling and Multiplication.

A two-party multiplication protocol between Alice and Bob is a protocol resulting in additive shares of the multiplication of Alice and Bob's secrets. In other words, Let $a$ be Alice's secret and $b$ be Bob's secret. The protocol outputs $\alpha$ to Alice and $\beta$ to Bob such that $a * b = \alpha + \beta$

The protocol we've implemented is batched ie. It allows parallel multiplication of `L` many inputs from Alice and Bob.

Trivially, by providing random values as `a` and/or `b`, this protocol becomes a randomized multiplication protocol.

Note that in DKLs23, a particular variant of this protocol is used that is called "Forced Reuse". Effectively, Bob has a single random input. The output of the protocol is multiplication of Bob's single input to the vector of Alice's inputs. As a consequence of randomizing Bob's input, this protocol will have one fewer rounds than the original version described in DKLs19.

We implement the forced-reuse variant of the DKLs19 multiplication protocol, setting L=2 as required by F_RVOLE.

The details of the main protocol are sketched in Protocol 1 of DkLs19 and the necessary modifications to this protocol for DKLs23 are described in Functionality 3.5 of DKLs23.

## Configuration

**Players**: 2 parties, A (Alice) and B (Bob)

**Parameters**:
- $\kappa$: a computational security parameter, $\kappa$ = |q| (for a field $\mathbb{Z}_q$). E.g. $\kappa$=256
- $\xi$: the COTe input batch size, set to $\xi$ = $\kappa$+2s
- L ∈ $\mathbb{N}$, the DKLs23 batch size in #elements
- g: public gadget vector (sampled from $\mathbb{Z}_{q}^{\xi}$).

**Functionalities**:
- `COTe(η)` Correlated Oblivious Transfer with $\eta$ choice bits.
- `H(x,L)` Hash function, input x of variable size, output of size $\mathbb{Z}_q^L$
- `Send(x)=> P` Send message x to party P.

**Inputs**:
- Alice: a=[ $a_{1}$, $a_{2}$ ] $\in \mathbb{Z}_q^L$, the input vector of Alice.

**Outputs**:
- Alice -> z_A ∈ $\mathbb{Z}_q^L$, the correlation of Alice    s.t. z_A + z_B = a • b
- Bob -> z_B ∈ $\mathbb{Z}_q^L$, the correlation of Bob        s.t. z_A + z_B = a • b

## Protocol

0. INIT:
    1. Unique session id `sid`.
    2. Compute COTe.Setup (init S&R in SoftspokenOT with [ $\kappa \times$ BaseOT] seeds)

1. Round 1 (Bob):
    1. samples random choice bits $\beta$ from $\mathbb{Z}_{\xi}$
    2. define a pad $\tilde{b}$. Note that $\tilde{b}$ is effectively bob's input.

   $\tilde{b}_j = g_j \cdot \beta_j$                                   $\in \mathbb{Z}_q, \forall{j}{\xi}$

    3. Initiate $COTe(\xi)$ Round 1 and receive `extendedPackedChoices`, `cOTeReceiverOutput` and `R1Output`. Cache the first two.
    4. Send `R1Output` to Alice.

2. Round 2 (Alice):

    0. receive `R1Output`
    1. Samples pads $\tilde{a}$ from $\mathbb{Z}^L$
    2. Samples check values $\hat{a}$ from $\mathbb{Z}^L$
    3. Compute $\alpha$ <br>
       Each of the L OTe batches of size ξ correlates OTeWidth=2 scalars\
       Replicate ξ times the elements of ã and â inside each of the L batches\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;α = {{ã_1, â_1}, || {{ã_2, â_2},  || ... || {{ã_L, â_L},    ∈ [L][ξ][2]ℤq\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{ã_1, â_1},     {ã_2, â_2},  || ... ||  {ã_L, â_L},\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{..., ...},     {..., ...},  || ... ||  {..., ...},\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{ã_1, â_1}}     {ã_2, â_2}}  || ... ||  {ã_L, â_L}}
    4. Initiate COTe round 2 with inputs `R1Output` and `a` and receive `cOTeSenderOutputs` and `R2Output`.
    5. Parse `cOTeSenderOutputs` as ($\tilde{z}_A=\[L\]\[\xi\]\[0\]z$, $\hat{z}_A=\[L\]\[\xi\]\[1\]z$) where $z \in \mathbb{Z}_q$\
            $\tilde{z}_A$ = cOTeSenderOutputs[:][:][0]&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// Every first element                $\in$ [L][$\xi$]$\mathbb{Z}_q$\
            $\hat{z}_A$ = cOTeSenderOutputs[:][:][1] &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// Every other element                $\in$ [L][$\xi$]$\mathbb{Z}_q$
    6. Compute $\tilde{\chi} \leftarrow H^{\xi}(1, sid, t)$ where t is the shared transcript of COTe.
    7. Compute $\hat{\chi} \leftarrow H^{\xi}(2, sid, t)$ where t is the shared transcript of COTe.
    8. Compute `u`:<br>
      $u = \sum_{i=0}^{L-1} {\tilde{\chi}_i \cdot \tilde{a}_i + \hat{\chi}_i + \hat{a}_i}$
    9. Compute `r`: <br>
$r_{i,j}=\tilde{\chi}_{i} \cdot \tilde{z_{A_{\xi}}} + \hat{\chi}_i \cdot $$\hat{z_{A_{\xi}}}$  $\in \mathbb{Z}_q, \forall{i}\in\[L\], \forall{j} \in \[ \xi \]$
    10. Compute $\tilde{r}$ by hashing `r` and `sid` to $\mathbb{Z}_q$.
    11. Compute $\gamma_A$:<br>
      $\gamma_A = \sum_{i=0}^{L-1} a_i - \tilde{a}_i$                                       $\in \mathbb{Z}_q$
    12. Derive `$\z_A$` (**This is the result for Alice**):<br>
      $z_A_i = \sum_{j=1}^{\xi} g_j \cdot \tilde{z}_A_{i_{j}}$                              $\in \mathbb{Z}_q, \forall{i} \in \[L\]$
    13. Sends ($gamma_A$, $\tilde{r}$, u, R2Output) to Bob.

3. Round 3 (Bob):

    0. Receive ($gamma_A$, $\tilde{r}$, u, R2Output) from Alice.
    1. Initiate COTe round 3 with inputs `R2Output`, `oteReceiverOutput` and `extendedPackedChoices` to receive `coteReceiverOutput`.
    2. Parse `cOTeReceiverOutputs` as ($\tilde{z}_B=\[L\]\[\xi\]\[0\]z$, $\hat{z}_B=\[L\]\[\xi\]\[1\]z$) where $z \in \mathbb{Z}_q$\
            $\tilde{z}_B$ = cOTeReceiverOutputs[:][:][0]&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// Every first element                $\in$ [L][$\xi$]$\mathbb{Z}_q$\
            $\hat{z}_B$ = cOTeReceiverOutputs[:][:][1] &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// Every other element                $\in$ [L][$\xi$]$\mathbb{Z}_q$
    3. Compute $\tilde{\chi} \leftarrow H^{\xi}(1, sid, t)$ where t is the shared transcript of COTe.
    4. Compute $\hat{\chi} \leftarrow H^{\xi}(2, sid, t)$ where t is the shared transcript of COTe.
    5. Bob computes $\tilde{r}_B$:<br>
     $\tilde{r_{B_{i,j}}} = \beta_j \cdot u_i + \tilde{\chi}_i \cdot \tilde{z_{B_{j}}} - \hat{\chi}_i \cdot \hat{z_{B_{j}}}$   $\in \mathbb{Z}_q, \forall{i} \in \[L\], \forall{j} \in \[\xi \]$
    6. **ABORT** if $\tilde{r}_B \neq \tilde{r}$
    7. Derive $z_B$ (**This is the result for Bob**):<br>
     $z_{B_i} = \tilde{b} \cdot \gamma_{A_i} + \sum_{j=1}^{\xi} g_j \cdot \tilde{z}_{B_j}$              $\in \mathbb{Z}_q, \forall{i} \in \[L\]$

## Correspondance to Functionality commands:
                  Step numbers
- Setup           [0.2]
- Sampling:       [1.1, 1.2]
- Multiplication: [Every thing else]

