# Description.  
The ARC4 Cryptography Provider Class Library is a DLL file for .NET projects that includes an implementation of a well-known symmetric encryption algorithm that is not present in the System.Security.Cryptography namespace of the mscorlib library.

The cryptographic algorithm, known as **ARC4** (**A**lleged **RC4**), is a stream cipher that is widely used in various information security systems on computer networks (for example, SSL and TLS protocols, WEP and WPA wireless security algorithms).
The original RC4 stream cipher was created by Ronald Rivest of RSA Security. For seven years, the cipher was a trade secret, and the exact description of the algorithm was provided only after the signing of a non-disclosure agreement, but in September 1994 its description was anonymously sent to the mailing list of Cypherpunks.

To avoid potential claims from the trademark owner, the cipher is sometimes referred to as ARC4, meaning to alleged RC4 (since RSA Security did not officially release the algorithm).

Despite the fact that this cipher is not recommended, ARC4 remains popular due to its simplicity of software implementation and high speed of operation. Another important advantage is the variable key length and the same amount of encrypted and original data. 

## Contents.
0. [Library contents.](#library-contents)
1. [Usage.](#usage)
2. [How it works.](#how-it-works)
    - [S-block initialization.](#s-block-initialization)
    - [Using custom S-block.](#using-custom-s-block)
    - [Generating a pseudo-random word K](#generating-a-pseudo-random-word-k)
    - [Cipher algorithm.](#cipher-algorithm)

## Library contents.  

- **System.Security.Cryptography** includes an implementation of the **SymmetricAlgorithm** and **DeriveBytes** base classes for the ARC4 algorithm.
- **System.IO** include an implementation of a stream that contains encrypted data using ARC4 algorithm.

## Usage.  

Copy the downloaded DLL file in a custom folder on your dev folder. Create a project in Visual Studio IDE. In Solution Explorer, right-click on the References or Dependencies node and choose either Add Project Reference, select file ARC4Lib.dll to add, and then press OK.  

To register the algorithm mapping names for the current application domain, try the following:  

```csharp
using System.Security.Cryptography;
// ...

ARC4.Register();
```

### Example of encryption and decryption data.  

 ```csharp
using System.Security.Cryptography;
// ...

byte[] password = Encoding.UTF8.GetBytes("password");
byte[] data = Encoding.UTF8.GetBytes("secret");
byte[] encrypted, restored;
using (var arc4 = ARC4.Create(password, ARC4SBlock.DefaultSBlock))
{
    using(var transform = arc4.CreateEncryptor()) // Encryption.
    {
        encrypted = transform.TransformFinalBlock(data, 0, data.Length);
    }

    using(var transform = arc4.CreateDecryptor()) // Decryption.
    {
        restored = transform.TransformFinalBlock(data, 0, data.Length);
    }
}
```

### Example of using cryptographic stream.  

```csharp
using System.Security.Cryptography;
// ...

string password = "password";
string data = "secret";
string restored;
using (var memory = new MemoryStream())
{ 
    // Encryption.
    using (var stream = new ARC4Stream(memory, password, ARC4SBlock.DefaultSBlock))
    { 
        using (StreamWriter writer = new StreamWriter(stream))
        {
            writer.Write(data);
        }
    }
    memory.Seek(0, SeekOrigin.Begin); // Reset the memory position to start.
    // Decryption.
    using (var stream = new ARC4Stream(memory, password, ARC4SBlock.DefaultSBlock))
    {
        using (StreamReader reader = new StreamReader(stream))
        {
            restored = reader.ReadToEnd();
        }
    }
}
```

## How it works.  

The core of the stream cipher algorithm consists of a function - a pseudo-random bit (gamma) generator, which produces a key bit stream (key stream, gamma, pseudo-random bit sequence). 

### S-block initialization.  

The algorithm is also known as the key-scheduling algorithm (**KSA**). This algorithm uses a key entered by the user, stored in Key, and has a length of L bytes. Initialization begins with filling the array (**S-block**), then this array is shuffled by permutations defined by the key. Since only one action is performed on S-block, the statement must be made that S-block always contains one set of values that was given during initialization: S[i] = i. The user can also enter his own version of the S-block using the initialization vector or generate a pseudo-random S-block (see next paragraph about it).    

<details><summary>View code...</summary>

```csharp
byte[] sblock = new byte[256]; // The array contained S-block.

void CreateSBlock()
{
    for (int i = 0; i < 256; i++)
    {
        sblock[i] = (byte)i; // S-block initialization.
    }
}

void KeyScheduling() (byte[] key) // KSA
{
    int j = 0, l = key.Length;
    for (int i = 0; i < 256; i++)
    {
        j = (j + sblock[i] + key[i % l]) % 256;
        Swap(sblock, i, j); // See below for "Swap" implementation ↓
    }
}
```

</details>

### Using custom S-block.  

**Attention!** By default (in this implementation) the S-box is initialized with a pseudo-random byte array obtained using the linear congruent method (**LCR**) before being passed to PGRA. This does not quite correspond to the classical algorithm, when the S-block was initialized with a sequence from 0 to 255 (S[i] = i). If classic behavior is required, use **ARC4SBlock.DefaultSBlock** as an initialization vector. Otherwise, you should always keep the initialization vector to prevent corruption of the decrypted data, because the encrypted data will be different each time the engine is initialized.  

<details><summary>See LCR details...</summary>
    
The essence of LCR method is to calculate a sequence of random numbers X[i], setting  

X[i+1] = (A • X[i] + C) MOD M, where:

- **M** is the modulus, (a natural number M ≥ 2 relative to which it calculates the remainder of the division);
- **A** is the factor (0 ≤ A < M);
- **C** is the increment (0 ≤ C < M);
- **X[0]** is the initial value 0 ≤ X[0] < M;
- index **i** changes sequentially within 0 ≤ i < M.

Thus, LCR creates a sequence of M non-duplicate pseudo-random values only when:  

- the numbers **С** and **M** are coprime;
- **B** = A - 1 multiple of **P** for every prime **P** that divides **M**;
- **B** is a multiple of 4 if **M** is a multiple of 4.

To generate an array of 256 unique bytes (values ​​from 0 to 255), we need the period of the sequence to be 256. This means that M must be equal to 256.  
In order for the LCR to generate a sequence with a period of 256, the parameters a and c must satisfy the following conditions:

- X[i+1] = R ⊕ (A • X[i] + C) MOD M
- X[i] ∈ (0, 256),
- X[0] is random start value,
- M = 256,
- R ∈ (0, 256) is random constant for best randomization,
- A and C must be coprime to M.
- A ∈ (1, 253) and A - 1 can be devided by 4,
- C ∈ (1, 255) and C must be an odd number.

To index array A we need 6 bits (since 2\^6 = 64), and to index array C we need 7 bits (since 2\^7 = 128). This means that to specify a pair of elements from A and C we need:
6 bits (for index in A) + 7 bits (for index in C) = 13 bits.

This leaves us with 3 unused bits. These bits will be the most significant bits of the indices A and C. The number s is obtained from the two most significant bits of index A and one most significant bit of index C
Then after LCR transformation each byte in sblock is rotated by a number s.

The upper bound for the number of distinct S-blocks that can be obtained using the folowing method is about 4 billion values.

```csharp
byte[] _A = // An array of 64 values that A.
{
    0x01, 0x05, 0x09, 0x0D, 0x11, 0x15, 0x19, 0x1D,
    0x21, 0x25, 0x29, 0x2D, 0x31, 0x35, 0x39, 0x3D,
    0x41, 0x45, 0x49, 0x4D, 0x51, 0x55, 0x59, 0x5D,
    0x61, 0x65, 0x69, 0x6D, 0x71, 0x75, 0x79, 0x7D,
    0x81, 0x85, 0x89, 0x8D, 0x91, 0x95, 0x99, 0x9D,
    0xA1, 0xA5, 0xA9, 0xAD, 0xB1, 0xB5, 0xB9, 0xBD,
    0xC1, 0xC5, 0xC9, 0xCD, 0xD1, 0xD5, 0xD9, 0xDD,
    0xE1, 0xE5, 0xE9, 0xED, 0xF1, 0xF5, 0xF9, 0xFD
};

byte[] _C = // An array of 128 values that C.
{
    0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F,
    0x11, 0x13, 0x15, 0x17, 0x19, 0x1B, 0x1D, 0x1F,
    0x21, 0x23, 0x25, 0x27, 0x29, 0x2B, 0x2D, 0x2F,
    0x31, 0x33, 0x35, 0x37, 0x39, 0x3B, 0x3D, 0x3F,
    0x41, 0x43, 0x45, 0x47, 0x49, 0x4B, 0x4D, 0x4F,
    0x51, 0x53, 0x55, 0x57, 0x59, 0x5B, 0x5D, 0x5F,
    0x61, 0x63, 0x65, 0x67, 0x69, 0x6B, 0x6D, 0x6F,
    0x71, 0x73, 0x75, 0x77, 0x79, 0x7B, 0x7D, 0x7F,
    0x81, 0x83, 0x85, 0x87, 0x89, 0x8B, 0x8D, 0x8F,
    0x91, 0x93, 0x95, 0x97, 0x99, 0x9B, 0x9D, 0x9F,
    0xA1, 0xA3, 0xA5, 0xA7, 0xA9, 0xAB, 0xAD, 0xAF,
    0xB1, 0xB3, 0xB5, 0xB7, 0xB9, 0xBB, 0xBD, 0xBF,
    0xC1, 0xC3, 0xC5, 0xC7, 0xC9, 0xCB, 0xCD, 0xCF,
    0xD1, 0xD3, 0xD5, 0xD7, 0xD9, 0xDB, 0xDD, 0xDF,
    0xE1, 0xE3, 0xE5, 0xE7, 0xE9, 0xEB, 0xED, 0xEF,
    0xF1, 0xF3, 0xF5, 0xF7, 0xF9, 0xFB, 0xFD, 0xFF
};

byte[] sblock = new byte[256];

void CreateRandomSBlock()
{
    using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
    {
        byte[] random = new byte[4];
        rng.GetBytes(random);
        int r = random[0];
        int x = random[1];
        int a = _A[random[2] % _A.Length];
        int c = _C[random[3] % _C.Length];
        int s = (byte)(((random[2] >> 6) & 0b11) | ((random[3] >> 7) & 1));
        const int m = 256;
        for (int i = 0; i < m; i++)
        {
            int b = (x = (a * x + c) & (m - 1)) ^ r;
            sblock[i] = (byte)((b << s) | (b >> (8 - s)));
        }
    }
}
```

</details>
                              
If you want to use your own S-block, it must be function **ValidBytes** tested. Tihs function checks that all 256 values should not be duplicated.  

<details><summary>View code...</summary>

```csharp
bool ValidBytes(byte[] bytes)
{
    if (bytes == null || bytes.Length != 256)
    {
        return false;
    }
    for (int i = 0; i < 256; i++)
    {
        for (int j = i + 1; j < 256; j++)
        {
            if (bytes[i] == bytes[j])
            {
                return false;
            }
        }
    }
    return true;
}
```

</details>
    
### Generating a pseudo-random word K.  
This part of the algorithm is called the pseudo-random generation algorithm (**PRGA**). The ARC4 keystream generator permutes the values stored in S-block. In one ARC4 cycle, one n-bit K word from the keystream is determined. In the future, the keyword will be added modulo two with the original text that the user wants to encrypt, and the encrypted text will be obtained.  

The **NextByte** function performs PRGA transformation and returns word K.  

<details><summary>View code...</summary>

```csharp
int x = 0, y = 0;
void Swap(byte[] array, int index1, int index2)
{
    byte b = array[index1];
    array[index1] = array[index2];
    array[index2] = b;
}

byte NextByte() // PRGA
{
    x = (x + 1) % 256;
    y = (y + sblock[x]) % 256;
    Swap(sblock, x, y);
    return sblock[(sblock[x] + sblock[y]) % 256];
}
```

</details>
    
### Cipher algorithm.  

#### Encryption.  

The function generates a sequence of bits K[i].
The bit sequence is then combined with the plaintext Mi by a modulo two (xor) operation. The result is a cipher code C[i]:  

- C[i] = M[i] ⊕ K[i].

#### Decryption.  

The key bitstream (keystream) Ki is re-created (regenerated).
The bitstream of the key is added with the cipher C[i] operation "XOR" (⊕). Due to the properties of the operation "XOR", the output is the original (unencrypted) text M[i]:  

- M[i] = C[i] ⊕ K[i] = ( M[i] ⊕ K[i] ) ⊕ K[i]  

The **Cipher** function performs symmetric encryption and decryption using the ARC4 algorithm.  

<details><summary>View code...</summary>

```csharp
void Cipher(byte[] buffer, int offset, int count)
{
    for (int i = offset; i < count; i++)
    {
        buffer[i] = unchecked((byte)(buffer[i] ^ NextByte()));
    }
}
```

</details>

________
[↑ Back to contents.](#contents)
