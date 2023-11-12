[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/KIVR.NET/blob/main/LICENSE)
# KIVR.NET
A .NET implementation of the [KIVR](https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/KIVR%20Context%20Committing%20Authenticated%20Encryption.pdf) [transform](https://csrc.nist.gov/Presentations/2023/kivr) for AEAD context commitment.

> **Note**
>
> KIVR should be implemented for a specific protocol with redundancy (e.g. magic bytes) rather than in a generic library like this to eliminate ciphertext expansion and plaintext copying overhead. Furthermore, an XOF or collision-resistant KDF should be used instead of a hash function to output a larger mask for greater (e.g. 128-bit) committing security.
