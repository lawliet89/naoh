# naoh
CLI tool to encrypt/decrypt files with libsodium

```bash
naoh 0.1.0
Yong Wen Chua 
Encrypt or decrypt a file based on `crypto_secretbox_xsalsa20poly1305`,a particular combination of Salsa20 and Poly1305 specified in Cryptography in NaCl
(http://nacl.cr.yp.to/valid.html).

USAGE:
    naoh [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help
            Prints help information

    -V, --version
            Prints version information


OPTIONS:
    -o, --output <path>
            Specify a path to output to. Defaults to STDOUT Existing files will be truncated. Use `-` to refer to STDOUT


SUBCOMMANDS:
    decrypt
            Decrypt a file with the provided key. By default, the last 24 bytes of the input
                        is assumed to be the nonce. This is the default output from the `encrypt` subcommand.
    encrypt
            Encrypt a file with the provided key. The output will include the encrypted payload, authentication tag, and by default the nonce used appended as
            the final 24 bytes.
    gen-key
            Generate a key for use with encryption or decryption

    gen-nonce
            Generate a nonce for use with encryption or decryption

    help
            Prints this message or the help of the given subcommand(s)

```
