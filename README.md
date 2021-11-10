## A lightweight and fast pure Elixir ECDSA

### Overview

This is an Elixir 1.9+ translation of [Stark Bank]\`s ecdsa-python. It is compatible with OpenSSL and uses elegant math such as Jacobian Coordinates to speed up the ECDSA on pure Elixir.

### Installation

To install [Stark Bank]\`s ECDSA-Elixir, add `starkbank_ecdsa` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:starkbank_ecdsa, "~> 1.1.0"}
  ]
end
```

### Curves

We currently support `secp256k1` and `prime256v1`, but it's super easy to add more curves to the project. Just add them on `lib/curve/knownCurves.ex`

### Speed

We ran a test on a MAC Pro i7 2017. The libraries were run 100 times and the averages displayed bellow were obtained:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| [crypto]           |     1.0ms     |  2.0ms  |
| starkbank_ecdsa    |     1.9ms     |  3.8ms  |

### Sample Code

How to sign a json message for [Stark Bank]:

```elixir
# Generate privateKey from PEM string
privateKey =
  EllipticCurve.PrivateKey.fromPem!("""
      -----BEGIN EC PARAMETERS-----
      BgUrgQQACg==
      -----END EC PARAMETERS-----
      -----BEGIN EC PRIVATE KEY-----
      MHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK
      oUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB
      RmpeRREXj5aog/Mq8RrdYy75W9q/Ig==
      -----END EC PRIVATE KEY-----
  """)

# Create message from json (using external Jason package: https://hexdocs.pm/jason/Jason.html)
message =
  Jason.encode!(%{
    transfers: [
      %{
        amount: 100_000_000,
        taxId: "594.739.480-42",
        name: "Daenerys Targaryen Stormborn",
        bankCode: "341",
        branchCode: "2201",
        accountNumber: "76543-8",
        tags: ["daenerys", "targaryen", "transfer-1-external-id"]
      }
    ]
  })

signature = EllipticCurve.Ecdsa.sign(message, privateKey)

# Generate Signature in base64. This result can be sent to Stark Bank in the request header as the Digital-Signature parameter.
signature
|> EllipticCurve.Signature.toBase64()
|> IO.puts()

# To double check if the message matches the signature, do this:
publicKey = privateKey |> EllipticCurve.PrivateKey.getPublicKey()

Ecdsa.verify?(message, signature, publicKey) |> IO.puts()
```

Simple use:

```elixir
# Generate new Keys
privateKey = EllipticCurve.PrivateKey.generate()
publicKey = EllipticCurve.PrivateKey.getPublicKey(privateKey)

message = "My test message"

# Generate Signature
signature = EllipticCurve.Ecdsa.sign(message, privateKey)

# To verify if the signature is valid
EllipticCurve.Ecdsa.verify?(message, signature, publicKey) |> IO.puts()
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
publicKeyPem = File.read!("publicKey.pem")
signatureDer = File.read!("signatureDer.txt")
message = File.read!("message.txt")

publicKey = EllipticCurve.PublicKey.fromPem!(publicKeyPem)
signature = EllipticCurve.Signature.fromDer!(signatureDer)

EllipticCurve.Ecdsa.verify?(message, signature, publicKey) |> IO.puts()
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
 
```python
signatureDer = File.read!("signatureDer.txt")

signature = EllipticCurve.Signature.fromDer!(signatureDer)

EllipticCurve.Signature.toBase64(signature) |> IO.puts()
```

### Run unit tests

```
mix test
```


[crypto]: https://elixir-lang.org/getting-started/erlang-libraries.html#the-crypto-module
[Stark Bank]: https://starkbank.com
