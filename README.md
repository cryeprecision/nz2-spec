# NZ2 Specification

Specification to allow for in-flight encryption of Usenet binary posts.

- This specification is a work-in-progress, contributions are welcome!
- Built PDFs are available in the [releases section](https://github.com/cryeprecision/nz2-spec/releases).

## Related Repositories

- [**NZ2 Specification**](https://github.com/cryeprecision/nz2-spec)
- [NZ2 Proof-of-Concept (Rust)](https://github.com/cryeprecision/nz2-poc-rs)
- [NNTP Client Library (Rust)](https://github.com/cryeprecision/nntp-rs)
- [rapidyenc (Fork)](https://github.com/cryeprecision/rapidyenc)
- [rapidyenc Rust Bindings](https://github.com/cryeprecision/rapidyenc-rs)
- [sabctools (Fork)](https://github.com/cryeprecision/sabctools)
- [sabnzbd (Fork)](https://github.com/cryeprecision/sabnzbd)

## Overview

- Uses only well-known cryptographic primitives.
  - Encryption is done using **ChaCha20-Poly1305 AEAD**.
  - Subkeys for each segment are derived using **HKDF** with **SHA256**.
  - Message-IDs are deterministically derived using **ChaCha20 RNG**.
- NZ2 files grow linearly with the number of referenced files, independent of their size.
  - An example NZB file for downloading a 15GiB file is 1.7MiB
  - The equivalent NZ2 file is 3.3kiB (99.8% smaller).
- Files within an NZ2 file *can* be added/removed without re-encrypting other files.
- Metadata like a file's path is cryptographically bound to its data.
- Usenet articles cannot be associated with each other without the encryption key.

For a more detailed overview, see the [PDFs](https://github.com/cryeprecision/nz2-spec/releases).
