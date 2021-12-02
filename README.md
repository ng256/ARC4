# Description.
The ARC4 Cryptography Provider Class Library is a DLL file that includes an implementation of a well-known symmetric encryption algorithm that is not present in the System.Security.Cryptography namespace of the mscorlib library.

The cryptographic algorithm, known as ARC4, is a stream cipher that is widely used in various information security systems on computer networks (for example, SSL and TLS protocols, WEP and WPA wireless security algorithms).
The RC4 stream cipher was created by Ronald Rivest of RSA Security. For seven years, the cipher was a trade secret, and the exact description of the algorithm was provided only after the signing of a non-disclosure agreement, but in September 1994 its description was anonymously sent to the mailing list of Cypherpunks.

To avoid potential claims from the trademark owner, the cipher is sometimes referred to as ARC4, meaning to alleged RC4 (since RSA Security did not officially release the algorithm).

Despite the fact that this cipher is not recommended, ARC4 remains popular due to its simplicity of software implementation and high speed of operation. Another important advantage is the variable key length and the same amount of encrypted and original data. 

# How it works.
The core of the stream cipher algorithm consists of a function - a pseudo-random bit (gamma) generator, which produces a key bit stream (key stream, gamma, pseudo-random bit sequence). 

## Encryption algorithm.
The function generates a sequence of bits Ki.
The bit sequence is then combined with the plaintext Mi by a modulo two (xor) operation. The result is a cipher code Ci: 

- Ci = Mi ⊕ Ki.

## Decryption algorithm.
The key bitstream (keystream) Ki is re-created (regenerated).
The bitstream of the key is added with the cipher Ci operation "xor". Due to the properties of the operation "xor", the output is the original (unencrypted) text Mi: 

- Mi = Ci ⊕ Ki = ( Mi ⊕ Ki ) ⊕ Ki

## S-box initialization.
The algorithm is also known as the key-scheduling algorithm (KSA). This algorithm uses a key entered by the user, stored in Key, and has a length of L bytes. Initialization begins with filling the array (S-block), then this array is shuffled by permutations defined by the key. Since only one action is performed on S-block, the statement must be made that S-block always contains one set of values that was given during the initial initialization: (S[i] := i).
The user can also enter his own version of the S-block using the initialization vector or generate a pseudo-random S-block.

## Generating a pseudo-random word K.
This part of the algorithm is called the pseudo-random generation algorithm (PRGA). The RC4 keystream generator permutes the values stored in S. In one RC4 cycle, one n-bit K word from the keystream is determined. In the future, the keyword will be added modulo two with the original text that the user wants to encrypt, and the encrypted text will be obtained. 

# Library contents.
- **System.Security.Cryptography** includes an implementation of the **SymmetricAlgorithm** and **DeriveBytes** base classes for the ARC4 algorithm.
- **System.IO** include an implementation of a stream that contains encrypted data using ARC4 algorithm.
