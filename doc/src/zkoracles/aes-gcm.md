# AES-GCM
GCM is an authenticated encryption with associated data (AEAD) cipher. 

To encrypt, the GCM cipher takes as inputs a tuple $(\sK,\sIV,\sP,\sA)$, where $\sK$ is a symmetric secret key, $\sIV$ is an initial vector, $\sP$ is a plaintext of multiple blocks (For AES-GCM, these are AES blocks), $\sA$ is the associated data to be included in the integrity protection. It outputs a ciphertext $\sC$ and a tag $\sT$.

To decrypt, it takes as inputs a tuple $(\sK,\sIV,\sC,\sA,\sT)$ and first checks the integrity of the ciphertext by comparing a recomputed $\sT'$ (from $\sK,\sIV,\sC,\sA$) with $\sT$, then outputs the plaintext.

- The length of $\sK$ is $16$ bytes.
- The length of $\sIV$ is $12$ bytes.
- The max length of $\sP$ is $2^{36} - 31$ bytes.
- The max length of $\sA$ is $2^{61} - 1$ bytes.
- The max length of $\sC$ is $2^{36}-15$ bytes.


Before describing the details of the specification, we define following functions. For a bit string $\sX$:

- $\int(\sX)$ is the integer for which the bit string $\sX$ is a binary representation.

- $\len(\sX)$ is the bit length of $\sX$.

- $\msb(\sX)_s$ is the bit string consisting of the $s$ left-most bits of $\sX$.

- $\lsb(\sX)_s$ is the bit string consisting of the $s$ right-most bits of $\sX$.

- $[x]_s$ is the binary representation of the non-negative integer $x$ as a string of $s$ bits.

- $\inc(\sX) = \msb_{\len(\sX)-32}(\sX)\|[\int(\lsb_{32}(\sX))+1\mod 2^{32}]_{32}$, where $\len(\sX) \geq 32$.

- Let $\sX$ and $\sY$ be 128-bit strings, denote $\sX\cdot\sY$ the multiplication in $\mathsf{GF}(2^{128})$ defined by the polynomial $x^{128}+x^7+x^2+x+1$.

## GHASH Function
The $\ghash$ function defined below is used to compute the tag.

1. $\ghash_\sH(\sX)$ takes as input a bit string $\sX$, whose length is $128m$ for some positive integer $m$. $\sH$ is a pre-defined $128$-bit string.

2. Let $\sX_1,...,\sX_m$ denote the sequence of 128-bit blocks such that $\sX = \sX_1\|...\|\sX_m$.

3. The function outputs $\sX_1\cdot \sH^m\oplus\sX_2\cdot \sH^{m-1}\oplus...\oplus\sX_m\cdot \sH$.


## AES-TCR Function
The $\tcr$ function defined below is used for encryption and decryption.
1. $\tcr(\sK,\icb,\sX)$ takes as inputs a $128$-bit key $\sK$, an initial $128$-bit counter block $\icb$ and a bit string $\sX$.

2. Let $n = \lceil \mathsf{len}(\sX)/128 \rceil$, and let ${\sX}_1,{\sX}_2,...,{\sX}_{n-1},{\sX}^*_n$ denote the unique blocks such that $\sX = {\sX}_1\|{\sX}_2\|...\|{\sX}_{n-1}\|{\sX}^*_n$. $\sX_1,...,\sX_{n-1}$ are complete blocks, $\sX^*_n$ is either a complete block or a nonempty partial block.
 
3. Let $\icb_1 = \icb$, for $i = 2$ to $n$, let $\icb_i = \inc(\icb_{i-1})$.

4. For $i = 1$ to $n-1$, let $\sY_i = \sX_i\oplus \aes(\sK,\icb_i)$.

5. Let $\sY^*_n = \sX^*_n\oplus \msb_{\len(\sX^*_n)}(\aes(\sK,\icb_n))$.

6. Let $\sY = \sY_1\|\sY_2\|...\|\sY^*_n$.

7. Output $\sY$.

## AES-GCM Specification
We now specify the AES-GCM encryption function. Note that only encryption is needed in zkOracles.

1. $\aesgcm(\sK,\sIV,\sP,\sA)$ takes as inputs a $128$-bit key $\sK$, an initial vector $\sIV$, a plaintext $\sP$ and associated data $\sA$.

2. Let $\sH = \aes(\sK,0^{128})$.

3. Let $\sJ_0$ be a $128$-bit block defined as follows: 
    - If $\len(\sIV) = 96$, then let $\sJ_0 = \sIV\|0^{31}\|1$.
    - If $\len(\sIV) \neq 96$, then let $s = 128\cdot \lceil \len(\sIV)/128\rceil -\len(\sIV)$, and let 
    $$\sJ_0 = \ghash_\sH(\sIV\|0^{s+64}\|[\len(\sIV)]_{64}).$$

4. Let $\sC = \tcr(\sK,\inc(\sJ_0),\sP)$.

5. Let $u = 128\cdot \lceil \len(\sC)/128\rceil -\len(\sC)$, $v = 128\cdot \lceil \len(\sA)/128\rceil -\len(\sA)$.

6. Define a $128$-bit block $\sS$ as follows:
$$\sS = \ghash_\sH(\sA\|0^v\|\sC\|0^u\|[\len(\sA)]_{64}\|[\len(\sC)]_{64}).$$

7. Let $\sT = \tcr(\sK,\sJ_0,\sS) = \aes(\sK,\sJ_0)\oplus\sS$.

8. Output $(\sC,\sT)$.

We refer the entire specification of AES-GCM to [this link](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

## Query Execution Protocol
The query execution protocol in zkOracles is essentially a two-party computation protocol that compute the AES-GCM encryption function. We specify it in details with some optimizations.

1. $\C$ takes as inputs $\sK_\C$ and $\sP$, $\N$ takes as a input $\sK_\N$, where $\sK_\C$, $\sK_\N$ are shares of a AES key. $\sIV$ and $\sA$ are public known messages.
    - Note that $\C$ and $\N$ should store used $\sIV$s, if a new $\sIV$ is used more than once, abort.

2. $\C$ and $\N$ take as inputs $\sK_\C$ and $\sK_\N$ respectively, and run $\pi^{\mathsf{PP}}_{\mathsf{2PC}}$ to generate shares pre-computed parameters $h_{\C,i}$ and $h_{\N,i}$ for $i\in[L]$ respectively. Where $L$ is determined by the length of $\sA$ and $\sP$.
    - Note that $h_{\C,i}\oplus h_{\N,i} = \sH^i$ for $\sH = \aes(\sK_\C\oplus\sK_\N,0^{128})$.

3. $\C$ and $\N$ compute $\sJ_0$ as follows:
    - If $\len(\sIV) = 96$, both party locally compute $\sJ_0 = \sIV\|0^{32}\|1$.
    - If $\len(\sIV) \neq 96$, let $s = 128\cdot\lceil\len(\sIV)/128\rceil-\len(\sIV)$. $\C$ and $\N$ take as inputs $h_{\C,i}$ and $h_{\N,i}$ for $i\in[L]$ respectively, and run the $\pi^{\mathsf{GHASH}}_{\mathsf{2PC}}$ protocol according to the input $\sX = \sIV\|0^{s+64}\|[\len(\sIV)]_{64}$.

4. $\C$ takes as inputs $\sK_\C$ and $\sP$, $\N$ takes as inputs $\sK_\N, 0^{128}$, and run the $\pi^{\mathsf{AES\text{-}TCR}}_{\mathsf{2PC}}$ protocol with public initial counter block $\inc(\sJ_0)$. $\C$ obtains the ciphertext $\sC$.

5. Let $u = 128\cdot \lceil \len(\sC)/128\rceil -\len(\sC)$, $v = 128\cdot \lceil \len(\sA)/128\rceil -\len(\sA)$.

6. $\C$ and $\N$ take as inputs $h_{\C,i}$ and $h_{\N,i}$ for $i\in[L]$ respectively, and run the $\pi^{\mathsf{GHASH}}_{\mathsf{2PC}}$ protocol according to the input $\sX = \sA\|0^v\|\sC\|0^u\|[\len(\sA)]_{64}\|[\len(\sC)]_{64}$. $\C$ obtains the share $\sS_\C$, $\N$ obtains the share $\sS_\N$.

7. $\C$ takes as inputs $\sK_\C$ and $\sS_\C$, $\N$ takes as inputs $\sK_\N$ and $\sS_\N$, and run the $\pi^{\mathsf{AES\text{-}TCR}}_{\mathsf{2PC}}$ protocol with public initial counter block $\sJ_0$. $\C$ obtains the ciphertext $\sT$.

8. $\C$ outputs $(\sC,\sT)$, $\N$ outputs nothing.
### The $\pi^{\mathsf{PP}}_{\mathsf{2PC}}$ Protocol
$\C$ samples uniformly random 128-bit strings $h_{\C,i}$ for $i\in[L]$, and securely computes the function $F_{\mathsf{PP}}((\sK_\C,h_{\C,1},...,h_{\C,L}),\sK_\N)$ with $\N$ as follows.

- Compute $\sH = \aes(\sK_\C\oplus\sK_\N,0^{128})$.

- Compute $h_{\N,i} = h_{\C,i}\oplus \sH^i$ for $i\in[L]$.

- Output $h_{\N,i}$ to $\N$, for $i\in[L]$.
### The $\pi^{\mathsf{GHASH}}_{\mathsf{2PC}}$ Protocol
Given a public input $\sX$, this protocol securely computes the $\ghash$ with pre-computed parameters. 
$\C$ samples uniformly random $128$-bit string $\sS_\C$.

- $\C$ and $\N$ takes as inputs $h_{\C,i}$ and $h_{\S,i}$ for $i\in[L]$, respectively. 

- Let $\sX = \sX_1\|\sX_2\|...\|\sX_L$.

- Compute $\sS = \sX_1\cdot (h_{\C,L}\oplus h_{\N,L})\oplus \sX_2\cdot(h_{\C,L-1}\oplus h_{\N,L-1})\oplus...\oplus\sX_L\cdot (h_{\C,1}\oplus h_{\N,1})$.

- Output $\sS_\N = \sS\oplus \sS_\C$ to $\N$, and output $\sS_\C$ to $\C$.
### The $\pi^{\mathsf{AES\text{-}TCR}}_{\mathsf{2PC}}$ Protocol
Given a public initial counter block $\icb$, this protocol securely computes the $\tcr$ function. 
$\C$ takes as inputs $\sK_\C$ and $\sP_\C$, $\N$ takes as inputs $\sK_\N$ and $\sP_\C$. They collaboratively  compute $\tcr(\sK_\C\oplus\sK_\N,\icb,\sP_\C\oplus\sP_\N)$, and the output is given to $\C$.