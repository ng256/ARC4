# Description.
The ARC4 Cryptography Provider Class Library is a DLL file for .NET projects that includes an implementation of a well-known symmetric encryption algorithm that is not present in the System.Security.Cryptography namespace of the mscorlib library.

The cryptographic algorithm, known as ARC4, is a stream cipher that is widely used in various information security systems on computer networks (for example, SSL and TLS protocols, WEP and WPA wireless security algorithms).
The RC4 stream cipher was created by Ronald Rivest of RSA Security. For seven years, the cipher was a trade secret, and the exact description of the algorithm was provided only after the signing of a non-disclosure agreement, but in September 1994 its description was anonymously sent to the mailing list of Cypherpunks.

To avoid potential claims from the trademark owner, the cipher is sometimes referred to as ARC4, meaning to alleged RC4 (since RSA Security did not officially release the algorithm).

Despite the fact that this cipher is not recommended, ARC4 remains popular due to its simplicity of software implementation and high speed of operation. Another important advantage is the variable key length and the same amount of encrypted and original data. 

## How it works.
The core of the stream cipher algorithm consists of a function - a pseudo-random bit (gamma) generator, which produces a key bit stream (key stream, gamma, pseudo-random bit sequence). 

### S-box initialization.
The algorithm is also known as the key-scheduling algorithm (KSA). This algorithm uses a key entered by the user, stored in Key, and has a length of L bytes. Initialization begins with filling the array (S-block), then this array is shuffled by permutations defined by the key. Since only one action is performed on S-block, the statement must be made that S-block always contains one set of values that was given during the initial initialization: (S[i] = i). The user can also enter his own version of the S-block using the initialization vector or generate a pseudo-random S-block.
```csharp
byte[] sblock = new byte[256]; // The array contained S-block.
void CreateSBlock()
{
    for (int i = 0; i < 256; i++)
    {
        sblock[i] = (byte)i; // S-Block initialization.
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

**Attention!** By default, in this implementation the S-block is initialized with a pseudo-random byte array obtained using the linear-congruential method (LCR). This does not quite correspond to the classical algorithm, when the S-block was initialized with a sequence from 0 to 255. If classic behavior is required, use **ARC4SBlock.DefaultSBlock** as an initialization vector. Otherwise, you should always keep the initialization vector to prevent corruption of the decrypted data, because the encrypted data will be different each time the engine is initialized.

The essence of LCR method is to calculate a sequence of random numbers X[i], setting

X[i+1] = (A • X [i] + C) MOD M, where:

- **M** is the modulus, (a natural number M ≥ 2 relative to which it calculates the remainder of the division);
- **A** is the factor (0 ≤ A < M);
- **C** is the increment (0 ≤ C < M);
- **X[0]** is the initial value 0 ≤ X[0] <M;
- index **i** in our case is within 0 ≤ i < 256.

Thus, LCR creates a sequence of 256 non-duplicate pseudo-random values.
```csharp
void CreateRandomSBlock()
{
    using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
    {
        byte[] random = new byte[4];
        rng.GetBytes(random);
        // For optimization it is calculated that:
        // x ∈ (0, 256),
        // a ∈ (5, 246),
        // c = 17,
        // m = 256.
        int x = BitConverter.ToInt32(random, 0) % 256;
        int a = 2;
        const int c = 17;
        const int m = 256;
        while ((a - 1) % 4 != 0)
        {
            random = new byte[4];
            rng.GetBytes(random);
            int rnd = BitConverter.ToInt32(random, 0);
            a = 5 + rnd % 246;
        }
        for (int i = 0; i < m; i++)
        {
            sblock[i] = (byte)(x = (a * x + c) % m); // S-Block initialization.
        }
    }
}
```
### Generating a pseudo-random word K.
This part of the algorithm is called the pseudo-random generation algorithm (PRGA). The RC4 keystream generator permutes the values stored in S-block. In one RC4 cycle, one n-bit K word from the keystream is determined. In the future, the keyword will be added modulo two with the original text that the user wants to encrypt, and the encrypted text will be obtained.
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

### Encryption algorithm.
The function generates a sequence of bits Ki.
The bit sequence is then combined with the plaintext Mi by a modulo two (xor) operation. The result is a cipher code Ci: 

- Ci = Mi ⊕ Ki.

### Decryption algorithm.
The key bitstream (keystream) Ki is re-created (regenerated).
The bitstream of the key is added with the cipher Ci operation "xor". Due to the properties of the operation "xor", the output is the original (unencrypted) text Mi: 

- Mi = Ci ⊕ Ki = ( Mi ⊕ Ki ) ⊕ Ki

```csharp
// Performs symmetric encryption and decryption using the ARC4 algorithm.
void Cipher(byte[] buffer, int offset, int count)
{
    for (int i = offset; i < count; i++)
    {
        buffer[i] = (byte)(buffer[i] ^ NextByte());
    }
}
```

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
    using(var transform = arc4.CreateEncryptor())
    {
        encrypted = transform.TransformFinalBlock(data, 0, data.Length);
    }

    using(var transform = arc4.CreateDecryptor())
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
    using (var stream = new ARC4Stream(memory, password, ARC4SBlock.DefaultSBlock))
    {
        using (StreamWriter writer = new StreamWriter(stream))
        {
            writer.Write(data);
        }
    }
    memory.Seek(0, SeekOrigin.Begin);
    using (var stream = new ARC4Stream(memory, password, ARC4SBlock.DefaultSBlock))
    {
        using (StreamReader reader = new StreamReader(stream))
        {
            restored = reader.ReadToEnd();
        }
    }
}

```
