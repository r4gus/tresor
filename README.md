# Tresor

Tresor is a simple, encrypted database for a small number of data sets.

Each secret (also called Entry) contains one or more key-value pairs (so called Fields).
The entries are stored in linear memory

A serialized key store is structured as follows:

1. The magic string "SECRET"
2. The length of the header
3. A CBOR encoded header
    * The major version number
    * The minor version number
    * A cipher identifier and the corresponding IV
    * A compression algorithm identifier (currently not supported)
    * A key derivation function identifier and corresponding parameters (e.g. number of rounds)
4. The TAG of a AEAD cipher
5. The AEAD encrypted CBOR data, with the header as associated data

## Encryption algorithms

The following encryption algorithms are supported:
    * ChaCha20

We can extend this library to support additional AEAD ciphers, if neccessary.


## Key Derivation Function

The following KDFs are supported:
    * Argon2id

We can extend this library to support additional KDFs, if neccessary.

## Info

* The data format doesn't store the length of the encrypted body! Please
  make sure that you store the serialized data in a way that allows you
  to infer the length of the body (e.g. when writing to a file, make sure
  you truncate the file to 0 byte before writing to it).
