## A lightweight and fast pure Elixir ECDSA

### Overview

This is an Elixir 1.9+ translation of [Stark Bank]'s ecdsa-python. It is compatible with OpenSSL and uses elegant math such as Jacobian Coordinates to speed up the ECDSA on pure Elixir.

### Security

starkbank-ecdsa includes the following security features:

- **RFC 6979 deterministic nonces**: Eliminates the catastrophic risk of nonce reuse that leaks private keys
- **Low-S signature normalization**: Prevents signature malleability (BIP-62)
- **Public key on-curve validation**: Blocks invalid-curve attacks during verification
- **Montgomery ladder scalar multiplication**: Constant-operation point multiplication to mitigate timing side channels
- **Hash truncation**: Correctly handles hash functions larger than the curve order (e.g. SHA-512 with secp256k1)
- **Extended Euclidean modular inverse**: Faster than Fermat's little theorem for 256-bit operands

### Installation

To install [Stark Bank]'s ECDSA-Elixir, add `starkbank_ecdsa` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:starkbank_ecdsa, "~> 2.0"}
  ]
end
```

### Curves

We currently support `secp256k1` and `prime256v1` (P-256), but you can add more curves to the project. You just need to use the `KnownCurves.add/1` function.

### Speed

We ran a test on Elixir 1.19.5 on a MAC Pro. The libraries were run 100 times and the averages displayed below were obtained:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| starkbank_ecdsa    |     0.6ms     |  0.9ms  |

Performance is driven by Jacobian coordinates, a Montgomery ladder for constant-time variable-base scalar multiplication, a precomputed window table (2^4-ary method) for the fixed generator used in signing, curve-specific shortcuts in point doubling (A=0 for secp256k1, A=-3 for prime256v1), Shamir's trick for combined scalar multiplication during verification, and the extended Euclidean algorithm for modular inversion.

### Sample Code

How to sign a json message for [Stark Bank]:

```elixir
alias EllipticCurve.{Ecdsa, PrivateKey, Signature}

# Generate privateKey from PEM string
{:ok, privateKey} = PrivateKey.fromPem("-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK
oUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB
RmpeRREXj5aog/Mq8RrdYy75W9q/Ig==
-----END EC PRIVATE KEY-----")

# Create message from json (using external Jason package: https://hexdocs.pm/jason/Jason.html)
message = Jason.encode!(%{
  transfers: [%{
    amount: 100_000_000,
    taxId: "594.739.480-42",
    name: "Daenerys Targaryen Stormborn",
    bankCode: "341",
    branchCode: "2201",
    accountNumber: "76543-8",
    tags: ["daenerys", "targaryen", "transfer-1-external-id"]
  }]
})

signature = Ecdsa.sign(message, privateKey)

# Generate Signature in base64. This result can be sent to Stark Bank in the request header as the Digital-Signature parameter.
IO.puts(Signature.toBase64(signature))

# To double check if the message matches the signature, do this:
publicKey = PrivateKey.getPublicKey(privateKey)

IO.puts(Ecdsa.verify?(message, signature, publicKey))
```

Simple use:

```elixir
alias EllipticCurve.{Ecdsa, PrivateKey}

# Generate new Keys
privateKey = PrivateKey.generate()
publicKey = PrivateKey.getPublicKey(privateKey)

message = "My test message"

# Generate Signature
signature = Ecdsa.sign(message, privateKey)

# To verify if the signature is valid
IO.puts(Ecdsa.verify?(message, signature, publicKey))
```

How to add more curves:

```elixir
alias EllipticCurve.{Curve, Point, PrivateKey, PublicKey}
alias EllipticCurve.Curve.KnownCurves

newCurve = %Curve{
  name: :frp256v1,
  A: 0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00,
  B: 0xee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f,
  P: 0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03,
  N: 0xf1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1,
  G: %Point{
    x: 0xb6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff,
    y: 0x6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb
  },
  oid: [1, 2, 250, 1, 223, 101, 256, 1]
}

KnownCurves.add(newCurve)

{:ok, publicKey} = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----
MFswFQYHKoZIzj0CAQYKKoF6AYFfZYIAAQNCAATeEFFYiQL+HmDYTf+QDmvQmWGD
dRJPqLj11do8okvkSxq2lwB6Ct4aITMlCyg3f1msafc/ROSN/Vgj69bDhZK6
-----END PUBLIC KEY-----")

IO.puts(PublicKey.toPem(publicKey))
```

How to generate compressed public key:

```elixir
alias EllipticCurve.{PrivateKey, PublicKey}

privateKey = PrivateKey.generate()
publicKey = PrivateKey.getPublicKey(privateKey)
compressedPublicKey = PublicKey.toCompressed(publicKey)

IO.puts(compressedPublicKey)
```

How to recover a compressed public key:

```elixir
alias EllipticCurve.PublicKey

compressedPublicKey = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
publicKey = PublicKey.fromCompressed(compressedPublicKey)

IO.puts(PublicKey.toPem(publicKey))
```

### OpenSSL

This library is compatible with OpenSSL, so you can use it to generate keys:

```
openssl ecparam -name secp256k1 -genkey -out privateKey.pem
openssl ec -in privateKey.pem -pubout -out publicKey.pem
```

Create a message.txt file and sign it:

```
openssl dgst -sha256 -sign privateKey.pem -out signatureDer.txt message.txt
```

To verify, do this:

```elixir
alias EllipticCurve.{Ecdsa, PublicKey, Signature}

{:ok, publicKeyPem} = File.read("publicKey.pem")
{:ok, signatureDer} = File.read("signatureDer.txt")
{:ok, message} = File.read("message.txt")

{:ok, publicKey} = PublicKey.fromPem(publicKeyPem)
{:ok, signature} = Signature.fromDer(signatureDer)

IO.puts(Ecdsa.verify?(message, signature, publicKey))
```

You can also verify it on terminal:

```
openssl dgst -sha256 -verify publicKey.pem -signature signatureDer.txt message.txt
```

NOTE: If you want to create a Digital Signature to use with [Stark Bank], you need to convert the binary signature to base64.

```
openssl base64 -in signatureDer.txt -out signatureBase64.txt
```

You can do the same with this library:

```elixir
{:ok, signatureDer} = File.read("signatureDer.txt")

{:ok, signature} = EllipticCurve.Signature.fromDer(signatureDer)

IO.puts(EllipticCurve.Signature.toBase64(signature))
```

### Run unit tests

```
mix test
```

### Run benchmark

```
mix run benchmark.exs
```


[crypto]: https://elixir-lang.org/getting-started/erlang-libraries.html#the-crypto-module
[Stark Bank]: https://starkbank.com
