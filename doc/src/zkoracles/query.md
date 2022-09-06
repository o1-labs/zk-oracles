# Query Execution
In a nutshell, the query execution phase is a two-party computation protocol that the Client and Notary collaboratively compute a ciphertext of the query hold by the Client. At the very beginning, the Client and Notary hold boolean shares of the symmetric key.

The detailed protocol of the query execution phase depends on the cipher suite used in TLS.

In this specification, we focus on AES-GCM and Chacha20-Poly1305.