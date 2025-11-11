#import "@preview/fontawesome:0.6.0"
#import "@preview/algorithmic:1.0.6"

#import algorithmic: algorithm-figure, style-algorithm
#import fontawesome: fa-icon

#let darkmode = true
#let text_color = if darkmode { luma(200) } else { luma(0) }
#let inline_emoji = text.with(top-edge: "bounds")

#show: style-algorithm.with(
  breakable: false,
  hlines: (
    grid.hline(stroke: 1pt + text_color),
    grid.hline(stroke: 1pt + text_color),
    grid.hline(stroke: 1pt + text_color),
  ),
)
#show raw: set text(font: "JetBrainsMono NF")

#set page(numbering: "1", fill: if darkmode { oklch(20%, 0.00, 0deg) })
#set text(fill: text_color)
#set table(stroke: text_color)

#set heading(numbering: (n1, ..x) => {
  numbering("1.1", if n1 - 1 < 0 { 0 } else { n1 - 1 }, ..x)
})
#set document(title: "NZB File Specification - E2EE Extension")

#let cleartext = [#text(fill: red, [cleartext])]
#let ciphertext = [#text(fill: green, [ciphertext])]
#let local = box(height: 0pt, text(fill: green, baseline: -10pt, fa-icon("desktop", size: 10pt)))
#let remote = box(height: 0pt, text(fill: red, baseline: -10pt, fa-icon("server", size: 10pt)))
#let good = box(width: 12pt, text(fill: green, fa-icon("circle-check", size: 9pt, solid: true)))
#let bad = box(width: 12pt, text(fill: red, fa-icon("circle-xmark", size: 9pt, solid: true)))
#let neutral = box(width: 12pt, text(fill: blue, fa-icon("circle-info", size: 9pt, solid: true)))
#let xml_segment = ```xml <segment>```
#let xml_nzb = ```xml <nzb>```
#let xml_head = ```xml <head>```
#let xml_file = ```xml <file>```
#let xml_meta = ```xml <meta>```
#let unit(qty, unit) = [#qty#h(2pt)#unit]

#let quote_(href, title, body) = block(
  breakable: false,
  stroke: red.transparentize(70%),
  radius: 1em,
  width: 100%,
  pad(x: 0pt, y: 1em, quote(
    attribution: [#link(href, title)],
    block: true,
    body,
  )),
)

#let roundbox = body => box(
  stroke: .5pt + text_color.transparentize(50%),
  radius: 9pt,
  pad(x: 1em, y: 1em, body),
)

#let interface_figure = (caption, body) => figure(
  caption: caption,
  roundbox(body),
)

#let appendix(body) = {
  set heading(numbering: "A.1", supplement: [Appendix])
  counter(heading).update(0)
  body
}

#outline(depth: 3)

= Disclaimer

The specification and security properties for this extension were created and derived using my own brain. While I do have some background knowledge of cryptography, I am by no means an expert. LLMs were used only to reword sentences. LLM outputs were always selectively applied.

#pagebreak(weak: true)
= Overview

The NZ2 format is not an extension of the NZB format but its own thing. It aims to be easy to implement and analyze by having only readily available dependencies and using well-known cryptographic primitives. It comes with the following properties

- Still uses yEnc-encoding at the core; compatible with rapidyenc @rapidyenc
- NZ2 files grow linearly with the number of referenced files, independent of their size
- No information leakage from yEnc headers/footers or article headers/body
- Posted atricles are impossible to correlate with one another without the NZ2 file
- The metadata of a file in the NZ2 file is cryptographically bound to its content
- Files are the basic unit of information and can be added/removed at will
- $approx 99.8%$ file size reduction compared to NZB files #footnote[An example NZB file referencing 11 files for a $approx #unit($15$, "GiB")$ reassembled file, having #box($approx 70$) character long filenames was compared with the equivalent NZ2 file. The NZB file was #unit($1.7$, "MiB"), the NZ2 file was #unit($3.3$, "kiB").]

An example for a NZ2 file is shown in @example-nz2.

#interface_figure[Example NZ2 file for downloading a single #unit($15$, "GiB") file][
  ```json
  {
    "nz2_version": "1.0.0",
    "encryption": { "algorithm": "ChaCha20-Poly1305-IETF" },
    "files": [{
      "path": "foo/bar/cat.jpg",
      "key": "w8Gae3CtJ3HKi09mflTAIm8mkcbexWUV1NydnZTpoTg=",
      "last_modified": 1760885192,
      "file_size": 16106127360,
      "segment_size": 1048576,
    }]
  }
  ```
] <example-nz2>

== Notes

- To allow compatibility with JavaScript, no integer should be larger than $2^53 - 1$ @max-safe-integer-js
- *The entire scheme relies on the fact that the file-key is generated from a properly seeded CSPRNG @csprng, the output of which must be indistinguishable from a truly random function*. If the file-key is generated from a low-entropy source of randomness, among other problems, the probability of ID collisions may become non-negligible and keys may become possible to bruteforce. *If the file-key is reused, the encryption is completely broken*!

== Definitions

- The key words _MUST_, _MUST NOT_, _REQUIRED_, _SHALL_, _SHALL NOT_, _SHOULD_, _SHOULD NOT_, _RECOMMENDED_, _MAY_, and _OPTIONAL_ are to be interpreted as described in RFC 2119 @rfc-keywords.
- Base64 refers to the RFC 4648 variant @base64-rfc, which is the default Base64 implementation in most cases. See @base64-variants-summary for a summary of Base64 variants and how to differentiate them.
- ChaCha20-Poly1305 refers to the IETF variant @chacha20-poly1305-ietf-rfc with 96-bit nonces and 32-bit internal counters. There also exists a non-IETF variant which uses 64-bit nonces and a XChaCha20-Poly1305-IETF variant which uses 192-bit nonces. We only use ChaCha20-Poly1305-IETF with 96-bit nonces @libsodium-aead. It is also common that ChaCha20-Poly1305 refers to the IETF-variant @iana-aead.
- For HKDF operations, this document uses the parameter names from RFC 5869 @hkdf-rfc, library documentation may use different terminology for the same parameters.
- Strings are always assumed to be in UTF-8; null terminators are not part of the string.
- Quantities like #unit($1$, "MB") mean #unit($10^6$, "bytes"); quantities like #unit($1$, "MiB") mean #unit($2^20$, "bytes").
- A "segment" refers to a contiguous part of a file. An "article" refers to an article on the usenet.

= Implementation

The following primitives are required to implement the NZ2 specification

- ChaCha20-Poly1305-IETF AEAD @chacha20-poly1305-ietf-rfc @libsodium-aead
- ChaCha20 CSPRNG @chacha20-csprng
- HKDF with SHA-256 @hkdf-rfc @hkdf-wikipedia @libsodium-hkdf @sha-function-comparison
- Base64 encoder/decoder @base64-rfc @base64-variants-summary
- JSON parser/serializer @json-rfc

== Key Generation <nz2-key-generation>

For each file to be uploaded, a new random #footnote[The file-key $k_"file"$ _MUST_ come from a CSPRNG @csprng that has been seeded with sufficient entropy.] file-key $k_"file"$ is generated from a CSPRNG. The subkeys $k_"enc"$ and $k_"id"$ are derived from $k_"file"$ using HKDF-SHA256. The encryption-key $k_"enc"$ is used as-is to encrypt segments. For each segment, the segment's index $i$ and the ID-key $k_"id"$ are used to derive the segment-specific subkeys $k_(i,"msg")$, $k_(i,"sub")$, and $k_(i,"pos")$, which are then used to seed ChaCha20 CSPRNGs and derive the Message-ID #footnote[Message-IDs still needs to be enclosed in '`<`' and '`>`', as specified in RFC 5536 section 3.1.3 @rfc-netnews-article-format.], Subject, and Poster respectively used to post the segment as an article. A graphical overview of this process is shown in @nz2-key-hierarchy-overview. The HKDF-parameters and an exact description of this process as pseudocode is shown in @nz2-key-derivation-algo and @nz2-segment-id-generation-algo.

While some extract-steps of HKDF @hkdf-rfc are not strictly necessary, since $k_"file"$ is already a random key, they are still included, as some libraries only provide combined extract-and-expand functions and do not expose the extract step separately.

#interface_figure[Uploading/downloading overview][
  ```
                   ╭──[Segment 1]──(Encrypt)──(Encode)──(Upload)──[Article 1]
  [File]──(Split)──╯──[Segment 2]──(Encrypt)──(Encode)──(Upload)──[Article 2]
                   ╰──[Segment N]──(Encrypt)──(Encode)──(Upload)──[Article N]

  [Article 1]──(Download)──(Decode)──(Decrypt)──[Segment 1]──╮
  [Article 2]──(Download)──(Decode)──(Decrypt)──[Segment 2]──╰──(Join)──[File]
  [Article N]──(Download)──(Decode)──(Decrypt)──[Segment N]──╯
  ```
] <nz2-upload-download-overview>

#interface_figure[Key hierarchy overview][
  ```
  [File-Key]─╮──(HKDF)──[Encryption-Key]   ╭──(HKDF)──(CSPRNG)──[Message-ID]
             │                             │
             ╰──(HKDF)──[ID-Key]────────╭──╯──(HKDF)──(CSPRNG)──[Subject]
                                        │  │
                       [Segment-Index]──╯  ╰──(HKDF)──(CSPRNG)──[Poster]
  ```
] <nz2-key-hierarchy-overview>

#interface_figure[Generating a new file-key $k_"file"$ and deriving the subkeys $k_"enc"$ and $k_"id"$][
  ```py
  def generate_keys():
    file_key = os.urandom(length: 32)
    prk = HKDF_SHA256.extract(salt: "nz2:1.0.0:file", ikm: file_key)

    enc_key = HKDF_SHA256.expand(prk, info: "encrypt", length: 32)
    id_key = HKDF_SHA256.expand(prk, info: "derive", length: 32)
    return (file_key, enc_key, id_key)
  ```
] <nz2-key-derivation-algo>

== ID Derivation <nz2-segment-id-generation>

An ID consists of 43 random alphanumeric characters and 2 fixed ones. Each character is sampled from the set $C = {"A".."Z", "a".."z", "0".."9"}$ using rejection sampling #footnote[For an explanation of why we use rejection sampling, read the comments in @rust-rand-alphnum-rejection-sampling.] @rust-rand-alphnum-rejection-sampling. This schema results in #box($approx #unit($256$, "bits")$) of randomness in each generated ID for a negligible collision probability, assuming $k_"file"$ contains sufficient entropy. The algorithm for deriving article IDs is shown in @nz2-segment-id-generation-algo. This schema is used to derive the Poster, Subject, and Message-ID for an article segment as shown in @nz2-key-hierarchy-overview.

The ChaCha20 CSPRNG is implemented as a ChaCha20 cipher with its 96-bit nonce set to all zeros, the seed is used as the 256-bit key, and the resulting keystream is consumed in 32-bit (4 byte) chunks, which are then interpreted as `u32`'s. This can be achieved by encrypting 32 bit worth of 0's. Test vectors are available in @appendix-test-vectors.

#interface_figure[Deriving IDs From $k_"id"$ Using Rejection Sampling][
  ```py
  def sample_alphanumeric_char(rng: ChaCha20_RNG):
    CHARS = (
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
      "abcdefghijklmnopqrstuvwxyz" +
      "0123456789"
    ) # len(CHARS) == 62

    while True:
      sample = rng.next_u32() >> (32 - 6)
      if sample < len(CHARS):
        return CHARS[sample]

  def sample_alphanumeric(rng: ChaCha20_RNG, chars):
    value = ""
    while len(value) < chars:
      value += sample_alphanumeric_char(rng)
    return value

  def sample_id(rng: ChaCha20_RNG):
    s_1 = sample_alphanumeric(rng, chars: 32)
    s_2 = sample_alphanumeric(rng, chars: 8)
    s_3 = sample_alphanumeric(rng, chars: 3)
    return s_1 + "@" + s_2 + "." + s_3

  def derive_id(id_key: Key, segment_index: u64, kind):
    info = []
    info += segment_index.to_le_bytes() # 64-bit
    info += kind.to_utf8_bytes()        # 24-bit (arbitrary limit)

    prk = HKDF_SHA256.extract(salt: "nz2:1.0.0:segment", ikm: id_key)
    seed = HKDF_SHA256.expand(prk, info, length: 32)
    rng = ChaCha20_RNG.with_seed(seed)
    return sample_id(rng)

  def derive_ids(id_key: Key, segment_index: u64):
    message_id = derive_id(id_key, segment_index, kind: "msg")
    subject = derive_id(id_key, segment_index, kind: "sub")
    poster = derive_id(id_key, segment_index, kind: "pos")
    return (message_id, subject, poster)
  ```
] <nz2-segment-id-generation-algo>

== File Splitting

Files are split into segments before encrypting, encoding, and uploading them as articles. A file is split by dividing it into non-overlapping segments of equal length, where the last segment may be smaller than the split size.

Assuming we split a file $F$ into segments of $s$ bytes, we split $F$ into
$
  n = ceil((|F|)/s)
$
segments $s_1, ..., s_n$. All segments $s_i$, except for the last one $s_n$, have the same size
$
    s & = |s_1| = ... = |s_(n-1)| \
  s_n & = |F| - s(n-1).
$
The sizes of individual segments add up to the size of the original file $sum_(i=1)^(n) |s_i| = |F|$.

== Encryption

In the following, we only look at encrypting a single file $F$, since files are independent of each other. We will build the associated data used for encryption across all segments of a file and the segment-specific nonces. The segment indices count segments (not bytes) and start at 0.

=== Associated Data

The associated data is built by packing the following items into a byte array:

- `[1:8]` --- The LE #footnote[Little-endian byte order] representation of the total file size in bytes as a `u64`
- `[9:16]` --- The LE representation of the segment size in bytes as a `u64`
- `[17:24]` --- The LE representation of the file's last modified timestamp as a `u64`
- `[25:]` --- The file's path encoded as UTF-8.

If the last modified timestamp can not be determined or the uploader does not want to include it, it _MUST_ be substituted with $0$ (zero). An example is shown in @nz2-associated-data-example.

#interface_figure[Example of associated data][
  ```
  ╭─1──2──3──4──5──6──7──8──┬─9──10─11─12─13─14─15─16─╮
  │ 00 94 35 77 00 00 00 00 │ 00 00 10 00 00 00 00 00 │
  ├─────────────────────────┼─────────────────────────┤
  │   File Size in Bytes    │  Segment Size in Bytes  │
  │ 2000000000 (0x77359400) │    1048576 (0x100000)   │
  ╰─────────────────────────┴─────────────────────────╯
  ╭─17─18─19─20─21─22─23─24─┬─25─26─27─28─29─╮
  │ D2 DA 08 69 00 00 00 00 │ 62 C3 A4 C3 9F │
  ├─────────────────────────┼────────────────┤
  │    Last Modified Time   │      Path      │
  │ 1762187986 (0x6908DAD2) │ "bäß" (UTF-8)  │
  ╰─────────────────────────┴────────────────╯
  ```
] <nz2-associated-data-example>

=== Nonces

The 96-bit nonce is built by packing the following items into a byte array:

- `[1:8]` --- The LE representation of the segment's index as a `u64`
- `[9:12]` --- Filled with zeros

An example is shown in @nz2-nonce-example.

#interface_figure[Example of a nonce][
  ```
  ┌─1──2──3──4──5──6──7──8──┬─9──10─11─12─┐
  │ BA 01 00 00 00 00 00 00 │ 00 00 00 00 │
  ├─────────────────────────┼─────────────┤
  │      Segment Index      │    Zeros    │
  │       442 (0x1BA)       │             │
  └─────────────────────────┴─────────────┘
  ```
] <nz2-nonce-example>

=== Ciphertext

The 128-bit tag produced by ChaCha20-Poly1305 _MUST_ be appended to the ciphertext. The process of deriving associated data, the nonce, and assembling the final ciphertext is shown in @nz2-segment-encryption.

#interface_figure[Segment encryption][
  ```py
  def encrypt_segment(
    file, enc_key, data,
    segment_index: u64,
    segment_size: u64
  ):
    assoc_data = []
    assoc_data += file.size.to_le_bytes()          # 64 bits
    assoc_data += segment_size.to_le_bytes()       # 64 bits
    assoc_data += file.last_modified.to_le_bytes() # 64 bits
    assoc_data += file.path.to_utf8_bytes()       # variable

    nonce = []
    nonce += segment_index.to_le_bytes()           # 64 bits
    nonce += [0, 0, 0, 0]                          # 32 bits

    ciphertext, tag = encrypt(data, enc_key, nonce, assoc_data)
    ciphertext += tag
    return ciphertext
  ```
] <nz2-segment-encryption>

== yEnc

Encrypted segments are yEnc encoded but _MUST NOT_ include yEnc headers or footers. All features of yEnc headers or footers are already covered by the base NZ2 format and its cryptographic guarantees. This means that the encoding and decoding logic is identical to yEnc @yenc-spec (without headers or footers) and fully compatible with the SIMD implementation rapidyenc @rapidyenc. Line widths used in yEnc encoding remain unchanged, common widths like 128 or 256 are _RECOMMENDED_.

== NZ2 File Structure

An NZ2 file is a UTF-8 encoded JSON file. The schema of the contained JSON is described in the following code snippets as TypeScript interfaces. There is also a JSON schema file available.

#align(center, box(
  grid(
    columns: (auto, auto),
    column-gutter: 3em,
    grid(
      rows: (auto, auto),
      row-gutter: 1.5em,
      [
        #interface_figure[Top-level NZ2 structure][
          ```ts
          interface Nz2 {
            nz2_version: string;
            encryption: Nz2Encryption;
            files: Nz2File[];
          }
          ```
        ] <nz2-structure-nz2>
      ],
      [
        #interface_figure[NZ2 Encryption options][
          ```ts
          interface Nz2Encryption {
            algorithm: "ChaCha20-Poly1305-IETF";
          }
          ```
        ] <nz2-structure-encryption>
      ],
    ),
    [
      #interface_figure[NZ2 File structure][
        ```ts
        interface Nz2File {
          path: string;
          key: string;
          last_modified?: number;
          file_size: number;
          segment_size: number;
        }
        ```
      ] <nz2-structure-file>
    ],
  ),
))

#block(breakable: false)[
  / `Nz2::version`: The version of this specification used.
    - This field _MUST_ be in SemVer format @semantic-versioning.
  / `Nz2Encryption::algorithm`: The AEAD primitive to use for encryption.
    - This field _MUST_ be set to `ChaCha20-Poly1305-IETF`.
  / `Nz2File::path`: A relative path describing where to store the downloaded file.
    - The path _MUST NOT_ contain path traversal elements.
    - The path _MUST NOT_ start or end with a path separator.
    - It is _RECOMMENDED_ that paths are canonicalized to achieve the above requirements.
  / `Nz2File::key`: The Base64-encoded 256-bit file-key $k_"file"$.
  / `Nz2File::last_modified`: An _OPTIONAL_ timestamp describing the file's last modified time.
    - The timestamp _MUST_ be a valid Unix timestamp in seconds since Unix epoch, UTC.
  / `Nz2File::file_size`: The size of the file to be downloaded in bytes without overhead.
  / `Nz2File::segment_size`: The size of each segment in bytes the file is split into.
]

= Threat Model

- Usenet providers should not be able to read or derive information from stored articles
- Usenet providers should not be able to modify the stored articles without detection
- Usenet providers should not be able to tell which articles belong together
- Integrity of NZ2 files is assumed. If the source of an NZ2 file is not trusted, minisign @minisign (or similar tools) can be used to verify the origin and integrity of a given NZ2 file

= Limitations

- ChaCha20-Poly1305 does not provide key robustness, we have to trust the NZ2 file
  - Out-of-scope: We assume integrity of the provided key
- The last segment of a file can be identified by the Usenet provider, as they may be smaller
  - Possible mitigation: Pad the last segment (causes large download overhead for many small files)
- Usenet providers can still associate articles using metadata. If segments are uploaded in close succession by the same IP address, there is a high probability that they belong together.
  - Out-of-scope: This may only be addressed effectively by upload clients.
- If a file-key is reused, beside the encryption being completely broken, posted articles will have the same Message-ID, Poster, and Subject and can be trivially correlated.
  - File-keys _MUST_ be generated from a properly seeded CSPRNG, so this is not a problem.

= Guarantees

By using the following properties:

+ Ciphertext integrity is verified for each segment during decryption
+ Integrity of the encryption key in the NZ2 file is assumed
+ The index of a given segment is used as the decryption nonce
+ File metadata and segment size are used as associated data
+ Message-ID, Poster, and Subject are derived using HKDF-SHA256 and the ChaCha20 CSPRNG

We can derive these guarantees:

- Each segment decrypts exactly to its original data, or decryption fails (1, 2)
- The segments are in the correct order, or decryption fails (3)
- No segments are missing and no segments have been added, or decryption fails (3, 4)
- Neither the path nor the last modified timestamp have been altered, or decryption fails (4)
- It is not possible to associate articles by their headers or content without the NZ2 file (5)

We thus know that on successful decryption, the reassembled segments are identical to the original file without any additional checksums or hashes over the reassembled file. Integrity of the file's path and last modified timestamp are to ensure that the metadata cannot be changed after encryption.

#pagebreak(weak: true)
#bibliography("bib.yml")

#pagebreak(weak: true)
#show: appendix

= Test Vectors <appendix-test-vectors>

== ChaCha20 CSPRNG

The test vectors in describe the expected output of a seeded ChaCha20 CSPRNG after 1 to 5 calls to `next_u32()`. The nonce of ChaCha20 is set to 12 zeros, the seed is used as the key.

#align(
  center,
  grid(
    columns: 2,
    gutter: 3em,
    figure(
      caption: [ChaCha20 CSPRNG Test Vectors \ 32-byte Seed: $#`0x00` times 32$],
      table(
        columns: 2,
        stroke: none,
        align: center,
        table.header[Call-Nr.][Output],
        table.hline(stroke: 0.5pt + text_color),
        [$1$], [`0xade0b876`],
        [$1 dot 2^12$], [`0x385a46ee`],
        [$2 dot 2^12$], [`0x02742d22`],
        [$3 dot 2^12$], [`0x88602327`],
      ),
    ),
    figure(
      caption: [ChaCha20 CSPRNG Test Vectors \ 32-byte Seed $#`0xFF` times 32$],
      table(
        columns: 2,
        stroke: none,
        align: center,
        table.header[Call-Nr.][Output],
        table.hline(stroke: 0.5pt + text_color),
        [$1$], [`0x4198b8f6`],
        [$1 dot 2^12$], [`0x2af06bd5`],
        [$2 dot 2^12$], [`0xaf06794c`],
        [$3 dot 2^12$], [`0xe88561b1`],
      ),
    ),
  ),
) <nz2-chacha20-csprng-test-vectors>

== ID Generation

The test vectors in @nz2-gen-id-test-vectors-00 and @nz2-gen-id-test-vectors-ff describe the expected output of the ID generation algorithm after 1 to 5 calls, using a ChaCha20 CSPRNG seeded with the given seed. The nonce of ChaCha20 is set to 12 zeros.

#figure(
  caption: [Generate ID Test Vectors \ 32-byte Seed: $#`0x00` times 32$],
  table(
    columns: 2,
    stroke: none,
    align: center,
    table.header[Call-Nr.][Output],
    table.hline(stroke: 0.5pt + text_color),
    [`1`], [`rk5KuGzxfjPN9HahvefDoaP7dQs1KRHb@54CdmxNX.aDH`],
    [`2`], [`EwY8WaqCIcNpgLEPVbfdr3sOK2RDyRhy@OzToRBF1.pk2`],
    [`3`], [`yGoUdIhTCDFYMSLRjEGXmwtLTwjCz5BD@m3Xg4F21.fSB`],
    [`4`], [`30SuoDE2uGfuZaeenpLzgOLFBYYvuBGd@wVxg8uYg.CvN`],
    [`5`], [`wFXv20LyC2VrxCLKwYfGalM8CWHPeqMg@AV2UZSEv.ieF`],
  ),
) <nz2-gen-id-test-vectors-00>

#figure(
  caption: [Generate ID Test Vectors \ 32-byte RNG Seed: $#`0xFF` times 32$],
  table(
    columns: 2,
    stroke: none,
    align: center,
    table.header[Call-Nr.][Output],
    table.hline(stroke: 0.5pt + text_color),
    [`1`], [`QYwoRsxcKX8odQMV2thkgmPyIyKGFtzU@kAUXh6Hc.tSq`],
    [`2`], [`ne7pG9cQTbY4QBN2Z1iv7HCGlRPiNlB8@9gM51E1t.08R`],
    [`3`], [`znIb3pt8k3ZxOotxrQCikogccz8Qqmk9@5azUhTFB.hnY`],
    [`4`], [`wif3gteK8oqV5vEOdz09LX5IrTdcvvu5@avWh0Ymg.sIM`],
    [`5`], [`0h3EdxTT2IxypHc1hJmYNtvJqcXofh9q@nAQAYQ1J.zdh`],
  ),
) <nz2-gen-id-test-vectors-ff>

== Key Derivation

The test vectors in @nz2-derive-key-test-vectors-00 and @nz2-derive-key-test-vectors-ff describe the expected derived subkeys $k_"enc"$ and $k_"id"$ when deriving them from the given file-key using HKDF-SHA256 and the in @nz2-key-generation and @nz2-segment-id-generation.

#figure(
  caption: [Derive Subkeys Test Vectors \ 32-byte File-Key: $#`0x00` times 32$],
  table(
    columns: 2,
    stroke: none,
    align: center,
    table.header[Key Name][Base64 Encoded Derived Key],
    table.hline(stroke: 0.5pt + text_color),
    [$k_"enc"$], [`SXCHftg+g/FdRlZ6AlRRbCEPv16w7tIGXqJn74m2tSA=`],
    [$k_"id"$], [`36/mff1sS26w2W9xIEYQ9IHerhdcbtPFwzGhmc+Koy4=`],
  ),
) <nz2-derive-key-test-vectors-00>

#figure(
  caption: [Derive Subkeys Test Vectors \ 32-byte File-Key: $#`0xFF` times 32$],
  table(
    columns: 2,
    stroke: none,
    align: center,
    table.header[Key Name][Base64 Encoded Derived Key],
    table.hline(stroke: 0.5pt + text_color),
    [$k_"enc"$], [`klOlmm52VO59xVaXE0jgc7XQBetYjgz6qfbzY2Sy7Ps=`],
    [$k_"id"$], [`lFlvUluZL/vaueafGGPaPwsJNgXpfZbgYAoc+ktmkDs=`],
  ),
) <nz2-derive-key-test-vectors-ff>

== Article ID Derivation

The test vectors in @nz2-derive-article-ids-test-vectors-00 and @nz2-derive-article-ids-test-vectors-ff describe the expected derived Message-ID, Subject, and Poster for the segment indices 0 to 4 using the given ID-Key and the algorithm in @nz2-segment-id-generation.

#figure(
  caption: [Derive Article IDs Test Vectors \ 32-byte ID-Key: $#`0x00` times 32$],
  table(
    columns: 3,
    stroke: none,
    align: center,
    table.header[Index][ID][Base64 Encoded Derived Key],
    table.hline(stroke: 0.5pt + text_color),
    [0], [Message-ID], [`R4NAnuY181vWV0rE2vfggn0hr5ImRWXJ@E5zLU1Pl.jv4`],
    [1], [Message-ID], [`csWNPuAQtp8wsCXxQGltm7X4qZrAm8rv@1XrmNxMN.gXq`],
    [2], [Message-ID], [`coyFwwSj4BHyFYyyKWEy7dSCLytpEj7D@kEv5uABo.hFw`],
    [3], [Message-ID], [`EzT1ZHu8LxP6LRKsfFxd5xP52HhtUTC2@gINwjMrn.ZeC`],
    [4], [Message-ID], [`zEvYtgoNFmfI4jTDbOGsi2LNW2no5R1q@NC5GW8mP.74u`],
    table.hline(stroke: 0.5pt + text_color),
    [0], [Subject], [`AoGbuE58MvNvGZoyXrjdvuhIuKsjjEEe@iM8MdKXu.9wX`],
    [1], [Subject], [`SKoPNIMp03N40b0M095p4yMkxIVGkdUb@I2wvGmeb.uxc`],
    [2], [Subject], [`VAYhfcOPFcFCZ0REsXYzwB3O74qW6ime@oZODtXU3.HO0`],
    [3], [Subject], [`nnsWRGKrtAJU7YpjYewPHlhOW5wbckFB@vdlxirvr.LQF`],
    [4], [Subject], [`PTny0GQtsdt4DRQSyqSpgfBdxx4wxudi@GK485qeR.H5e`],
    table.hline(stroke: 0.5pt + text_color),
    [0], [Poster], [`I9fkzYaGxXGOkCXl5lrnjQba3vTdPCGF@KoOhI9e0.fCw`],
    [1], [Poster], [`6VMn8QfH1PLin2tQYWo1kAABAN6R9Qc8@LwDEWPAo.4m6`],
    [2], [Poster], [`APUF2MBQkRewJn6qqMtRC2PpWdYYB0wq@Ko7tu2GQ.mM0`],
    [3], [Poster], [`pJJnt3ypPgLXwLLS7seHUW9FZhxsyCb6@Ib27yxsU.Ukr`],
    [4], [Poster], [`lhnBpTIliPunTF0gMXTNYJRn2NYT2LsD@wY17YfBp.Jfr`],
  ),
) <nz2-derive-article-ids-test-vectors-00>

#figure(
  caption: [Derive Article IDs Test Vectors \ 32-byte ID-Key: $#`0xFF` times 32$],
  table(
    columns: 3,
    stroke: none,
    align: center,
    table.header[Index][ID][Base64 Encoded Derived Key],
    table.hline(stroke: 0.5pt + text_color),
    [0], [Message-ID], [`l4qmBVuaUtosiHJDIkVFfNjtabtzfzgv@zmqxYgya.uY4`],
    [1], [Message-ID], [`Z1tPWZzIzTb5KdVoLu3vZuj4WoB1e00b@Upw6d0hM.2BS`],
    [2], [Message-ID], [`uSbrAmoj6APfldfgWYiGPaZG7alUgHz3@xxyG61O7.HMl`],
    [3], [Message-ID], [`Q16sTds3rUZuerrtUHQnBA0JYA0FRQpb@Sv8rY838.2Bg`],
    [4], [Message-ID], [`7l65irxQhCn5v4LBf2kHrru38wYz0mp1@TyC7hxEE.ZGz`],
    table.hline(stroke: 0.5pt + text_color),
    [0], [Subject], [`0WisDbzc3Dhr6KQEhpF16Q0XNAfTpNNI@sByUXNzQ.v4C`],
    [1], [Subject], [`xp6i9arqg8HXItIsxqrDuUoISscfsmbT@lInB7CgY.VOm`],
    [2], [Subject], [`mqL7UnM8zoUHbhyInjsWGWu5ljIzLIN8@GujHoMtE.fcJ`],
    [3], [Subject], [`oTnMMMjDULAuJ9kzfZdpK60erLkf15mh@X2AHrU7B.Icq`],
    [4], [Subject], [`VFB4LLok9VegXeBRreBFrpb5DGIPmUw6@BeGt63hg.Mkj`],
    table.hline(stroke: 0.5pt + text_color),
    [0], [Poster], [`5U7mXSmxAG7nQoBPKOcy1iGAR15uodtW@Iqxm78W2.x4r`],
    [1], [Poster], [`ggZQcMIPthnlr0GqGkJOXOOUJ0oe6Xyn@tWWvXlIi.lqM`],
    [2], [Poster], [`brxnLUXAXG6VQnayEXvXKZ2zf8LxfTtV@tirWogbV.bxa`],
    [3], [Poster], [`eHYrYoSz3SAweM80pA0rX2mugs47IKsL@UITdLv1J.OCU`],
    [4], [Poster], [`bsiP1DivzMqLaBnIL4V8cQ6pnKL0Sj52@mkEqUpK3.UtK`],
  ),
) <nz2-derive-article-ids-test-vectors-ff>

== Segment Encryption

The test vectors in @nz2-segment-encrypt-test-vectors describe the expected ciphertext and cleartext when encrypting and decrypting with the parameters listed below. The Trophy Emoji (#h(2pt)#inline_emoji[#emoji.trophy]#h(-1pt)) has the Unicode codepoint `U+1F3C6` and the UTF-8 encoding `f0 9f 8f 86`. Tests _SHOULD_ also ensure that decryption fails when the ciphertext, associated data, nonce, or key is modified.

- Key: $#`0x00` times 32$
- Associated Data:
  - Total Nr. of Segments: `2`
  - Last Modified Timestamp: `420`
  - File Path: "`foo/bar/cool.hc`"

#figure(
  caption: [Encryption Test Vectors],
  table(
    columns: 4,
    stroke: none,
    align: center,
    table.header[Segment][Base64 encoded Ciphertext][Cleartext][Base64 encoded UTF-8 Cleartext],
    table.hline(stroke: 0.5pt + text_color),
    [`0`], [`y2KKzjk0dylHfbAOZWC93dU+WW+LvirA`], ["`TempleOS`"], [`VGVtcGxlT1M=`],
    [`1`], [`EpWEnZc1OG4+HoQm3KlQPwM9CqQHLW6MxS0=`], ["`Terry 🏆`#h(-2pt)"], [`VGVycnkg8J+Phg==`],
  ),
) <nz2-segment-encrypt-test-vectors>

= yEnc Cheatsheet

In case rapidyenc @rapidyenc is not available, or your current yEnc implementation/library does not support encoding/decoding yEnc without headers and footers, this section provides a quick reference of the necessary encoding and decoding steps. Critical characters are idential to yEnc and listed in @nz2-yenc-critical-characters.

#figure(
  caption: [Critical Characters],
  table(
    columns: 4,
    stroke: (x: none, y: 0.5pt + text_color),
    align: (left, center, center, center),
    table.header[Name][Value][$b$][$pi_1^(-1)(b)$],
    [`NULL`], ["`\0`"], [`0x00`], [`0xD6`],
    [`LF`], ["`\n`"], [`0x0A`], [`0xE0`],
    [`CR`], ["`\r`"], [`0x0D`], [`0xE3`],
    [`EQ`], ["`=`"], [`0x3D`], [`0x13`],
    [`DOT`], ["`.`"], [`0x2E`], [`0x04`],
    [`SPACE`], ["` `"], [`0x20`], [`0xF6`],
    [`TAB`], ["`\t`"], [`0x09`], [`0xDF`],
  ),
) <nz2-yenc-critical-characters>

== Decoding <nz2-yenc-decode>

We keep our definitions from @nz2-yenc-encode. To decode a stream of bytes, use @nz2-yenc-decode-algorithm.

#algorithm-figure(
  "yEnc Decode",
  vstroke: .5pt + text_color.transparentize(50%),
  {
    import algorithmic: *
    Procedure("Decode", ("Reader", "Writer", "Width"), {
      While($"Reader.has_next()"$, {
        Assign[$b$][$"Reader.read()"$]
        IfElseChain(
          $b = #`EQ`$,
          {
            Assign[$b'$][$"Reader.read()"$]
            Line[$"Writer.write("pi_2^(-1)(b')")"$]
          },
          $b = #`CR`$,
          {
            LineComment(Assign[$\_$][$"Reader.read()"$])[Discard the `LF`]
          },
          {
            Line[$"Writer.write("pi_1^(-1)(b)")"$]
          },
        )
      })
    })
  },
) <nz2-yenc-decode-algorithm>

== Encoding <nz2-yenc-encode>

We define the following permutations that each map one byte to another

$
       pi_1 & : b |-> (b + 42) mod 256 \
  pi_1^(-1) & : b |-> (b - 42 + 256) mod 256 \
       pi_2 & : b |-> (b + 42 + 64) mod 256 \
  pi_2^(-1) & : b |-> (b - 42 - 64 + 256) mod 256
$

where $pi_1$ is the normal encoding, $pi^(-1)$ reverses $pi_1$, $pi_2$ is used to encode an escaped byte, and $pi_2^(-1)$ reverses $pi_2$. To encode a stream of bytes, use @nz2-yenc-encode-algorithm.

#algorithm-figure(
  "yEnc Encode",
  vstroke: .5pt + text_color.transparentize(50%),
  {
    import algorithmic: *
    Procedure("Encode", ("Reader", "Writer", "Width"), {
      Assign[$l$][$0$]
      While($"Reader.has_next()"$, {
        Assign[$b$][$"Reader.read()"$]
        Assign[$s$][$l = 0$]
        Assign[$e$][$l = "Width" - 1$]
        IfElseChain(
          $pi_1(b) in {#`NULL`, #`LF`, #`CR`, #`EQ`}$,
          {
            Line[$"Writer.write("#`EQ`", "pi_2(b)")"$]
            Assign($l$, $l + 2$)
          },
          $pi_1(b) in {#`SPACE`, #`TAB`} #`and` (s #`or` e)$,
          {
            Line[$"Writer.write("#`EQ`", "pi_2(b)")"$]
            Assign($l$, $l + 2$)
          },
          $pi_1(b) = #`DOT` #`and` s$,
          {
            Line[$"Writer.write("#`EQ`", "pi_2(b)")"$]
            Assign($l$, $l + 2$)
          },
          {
            Line[$"Writer.write("pi_1(b)")"$]
            Assign($l$, $l + 1$)
          },
        )
        If($l >= "Width"$, {
          Line[$"Writer.write("#`CR`", "#`LF`")"$]
          Assign($l$, $0$)
        })
      })
    })
  },
) <nz2-yenc-encode-algorithm>
