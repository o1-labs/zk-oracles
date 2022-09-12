# Commit
This section describes the Commit phase of zkOracles protocol.

- After the Client $\C$ and the Notary $\N$ run the Query Execution phase, the Client $\C$ generates a ciphertext $\sQ'$ of query $\sQ$ under the underlying cipher suite. $\C$ and $\N$ hold the secret key shares $\sK_\C$ and $\sK_\N$, respectively.

- The Client sends $\sQ'$ to the Server $\S$, the Server responds with a ciphertext $\sR'$. Note that $\S$ always responds honestly.

- The Client generates a commitment of his share $\sK_\C$ by computing $\com_\C = \sha(\sK_\C\|r)$, where $r$ is 128-bit uniformly random string. $\C$ sends $\com_\C\|\sQ'\|\sR'$ to the Notary $\N$.

- The Notary signs $\com_\C\|\sQ'\|\sR'\|\sK_N$ with his public key and outputs a signature $\sigma_\N$. The Notary sends $\com_\C\|\sQ'\|\sR'\|\sK_N\|\sigma_\N$ to the Client.

- The Client recover the symmetric key $\sK = \sK_\C\oplus\sK_\N$ to decrypt and authenticate $\sR'$. This step is exactly the same as in the TLS standard.


