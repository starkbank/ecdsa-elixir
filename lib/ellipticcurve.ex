defmodule EllipticCurve do
  @moduledoc """
  Pure Elixir package used to generate and read private/public key pairs in PEM and DER formats,
  sign and verify messages using the Elliptic Curve Digital Signature Algorithm (ECDSA).

  Security features:
  - RFC 6979 deterministic nonces
  - Low-S signature normalization (BIP-62)
  - Public key on-curve validation
  - Montgomery ladder scalar multiplication
  - Hash truncation for oversized hashes
  - Fermat's little theorem for modular inverse
  - Shamir's trick for fast verification
  - Tonelli-Shanks for modular square root

  Submodules:
  - Ecdsa: verifies and signs messages;
  - Signature: loads and dumps signatures;
  - PrivateKey: creates, loads and dumps private keys; also creates public keys from private keys;
  - PublicKey: loads and dumps public keys;
  """
end
