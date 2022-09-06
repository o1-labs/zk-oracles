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

## $\ghash$ Function
The $\ghash$ function defined below is used to compute the tag.

- $\ghash_\sH(\sX)$ takes as input a bit string $\sX$, whose length is $128m$ for some positive integer $m$. $\sH$ is a pre-defined $128$-bit string.

- Let $\sX_1,...,\sX_m$ denote the sequence of 128-bit blocks such that $\sX = \sX_1\|...\|\sX_m$.

- The function outputs $\sX_1\cdot \sH^m\oplus\sX_2\cdot \sH^{m-1}\oplus...\oplus\sX_m\cdot \sH$.


## $\tcr$ Function
The $\tcr$ function defined below is used for encryption and decryption.
- $\tcr(\sK,\icb,\sX)$ takes as inputs a $128$-bit key $\sK$, an initial $128$-bit counter block $\icb$ and a bit string $\sX$.

- Let $n = \lceil \mathsf{len}(\sX)/128 \rceil$, and let ${\sX}_1,{\sX}_2,...,{\sX}_{n-1},{\sX}^*_n$ denote the unique block such that $\sX = {\sX}_1\|{\sX}_2\|...\|{\sX}_{n-1}\|{\sX}^*_n$. $\sX_1,...,\sX_{n-1}$ are complete blocks, $\sX^*_n$ is either a complete block or a nonempty partial block.
 
- Let $\icb_1 = \icb$, for $i = 2$ to $n$, let $\icb_i = \inc(\icb_{i-1})$.

- For $i = 1$ to $n-1$, let $\sY_i = \sX_i\oplus \aes(\sK,\icb_i)$.

- Let $\sY^*_n = \sX^*_n\oplus \msb_{\len(\sX^*_n)}(\aes(\sK,\icb_n))$.

- Let $\sY = \sY_1\|\sY_2\|...\|\sY^*_n$.

- Output $\sY$.

## $\aesgcm$ Specification
We now specify the AES-GCM encryption function. Note that only encryption is needed in zkOracles.

- $\aesgcm(\sK,\sIV,\sP,\sA)$ takes as inputs a $128$-bit key $\sK$, an initial vector $\sIV$, a plaintext $\sP$ and associated data $\sA$.

- Let $\sH = \aes(\sK,0^{128})$.

- Let $\sJ_0$ be a $128$-bit block defined as follows: 
    - If $\len(\sIV) = 96$, then let $\sJ_0 = \sIV\|0^{31}\|1$.
    - If $\len(\sIV) \neq 96$, then let $s = 128\cdot \lceil \len(\sIV)/128\rceil -\len(\sIV)$, and let 
    $$\sJ_0 = \ghash_\sH(\sIV\|0^{s+64}\|[\len(\sIV)]_{64}).$$

- Let $\sC = \tcr(\sK,\inc(\sJ_0),\sP)$.

- Let $u = 128\cdot \lceil \len(\sC)/128\rceil -\len(\sC)$, $v = 128\cdot \lceil \len(\sA)/128\rceil -\len(\sA)$.

- Define a $128$-bit block $\sS$ as follows:
$$\sS = \ghash_\sH(\sA\|0^v\|\sC\|0^u\|[\len(\sA)]_{64}\|[\len(\sC)]_{64}).$$

- Let $\sT = \tcr(\sK,\sJ_0,\sS) = \aes(\sK,\sJ_0)\oplus\sS$.

- Output $(\sC,\sT)$.

We refer the entire specification of AES-GCM to [this link](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).