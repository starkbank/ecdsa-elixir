defmodule EllipticCurve.Ecdsa do
  @moduledoc """
  Used to sign and verify signatures using the Elliptic Curve Digital Signature Algorithm

  Functions:
  - sign()
  - verify()
  """

  alias EllipticCurve.{PrivateKey, PublicKey}

  @doc """
  Generates a message signature based on a private key

  Parameters:
  - message [string]: message that will be signed
  - privateKey [private key secret integer]: private key associated with the signer
  - options [keyword list]: refines request
    - hashfunc [:method]: defines the hash function applied to the message. Must be compatible with :crypto.hash;

  Returns {:ok, signature}:
  - signature [string]: base-64 message signature;

  ## Example:

      iex> EllipticCurve.Ecdsa.sign("my message", privateKey)
      {:ok, YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE=}
  """
  def sign(message, privateKey, options \\ []) do
    %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})

    :crypto.hash(hashfunc, message)
    |> PrivateKey.sign(privateKey)
  end

  @doc """
  Verifies a message signature based on a public key

  Parameters:
  - message [string]: message that will be signed
  - signature [base64 string]: signature associated with the message
  - publicKey [public key secret integer]: public key associated with the message signer
  - options [keyword list]: refines request
    - hashfunc [:method]: defines the hash function applied to the message. Must be compatible with :crypto.hash;

  Returns {:ok, verified}:
  - verified [bool]: true if message, public key and signature are compatible, false otherwise;

  ## Example:

      iex> EllipticCurve.Ecdsa.verify(message, signature, publicKey)
      {:ok, true}
      iex> EllipticCurve.Ecdsa.verify(wrongMessage, signature, publicKey)
      {:ok, false}
      iex> EllipticCurve.Ecdsa.verify(message, wrongSignature, publicKey)
      {:ok, false}
      iex> EllipticCurve.Ecdsa.verify(message, signature, wrongPublicKey)
      {:ok, false}
  """
  def verify(message, signature, publicKey, hashfunc \\ :sha256) do
    :crypto.hash(hashfunc, message)
    |> PublicKey.verify(publicKey)
  end
end
