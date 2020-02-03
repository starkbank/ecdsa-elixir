defmodule EllipticCurve.Ecdsa do
  @moduledoc """
  Used to sign and verify signatures using the Elliptic Curve Digital Signature Algorithm

  Functions:
  - sign()
  - verify?()
  """

  alias EllipticCurve.Utils.{BinaryAscii, Math}
  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Signature.Data, as: Signature

  @doc """
  Generates a message signature based on a private key

  Parameters:
  - message [string]: message that will be signed
  - privateKey [private key secret integer]: private key associated with the signer
  - options [keyword list]: refines request
    - hashfunc [:method]: defines the hash function applied to the message. Must be compatible with :crypto.hash;

  Returns signature:
  - signature [string]: base-64 message signature;

  ## Example:

      iex> EllipticCurve.Ecdsa.sign("my message", privateKey)
      {:ok, YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE=}
  """
  def sign(message, privateKey, options \\ []) do
    %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})

    numberMessage =
      :crypto.hash(hashfunc, message)
      |> BinaryAscii.numberFromString()

    curveData = privateKey.curve

    randNum = IntegerUtils.between(1, curveData."N" - 1)

    r =
      Math.multiply(curveData."G", randNum, curveData."A", curveData."P", curveData."N").x
      |> IntegerUtils.modulo(curveData."N")

    s =
      ((numberMessage + r * privateKey.secret) * Math.inv(randNum, curveData."N"))
      |> IntegerUtils.modulo(curveData."N")

    %Signature{r: r, s: s}
  end

  @doc """
  Verifies a message signature based on a public key

  Parameters:
  - message [string]: message that will be signed
  - signature [base64 string]: signature associated with the message
  - publicKey [public key secret integer]: public key associated with the message signer
  - options [keyword list]: refines request
    - hashfunc [:method]: defines the hash function applied to the message. Must be compatible with :crypto.hash;

  Returns:
  - verified [bool]: true if message, public key and signature are compatible, false otherwise;

  ## Example:

      iex> EllipticCurve.Ecdsa.verify?(message, signature, publicKey)
      {:ok, true}
      iex> EllipticCurve.Ecdsa.verify?(wrongMessage, signature, publicKey)
      {:ok, false}
      iex> EllipticCurve.Ecdsa.verify?(message, wrongSignature, publicKey)
      {:ok, false}
      iex> EllipticCurve.Ecdsa.verify?(message, signature, wrongPublicKey)
      {:ok, false}
  """
  def verify?(message, signature, publicKey, options \\ []) do
    %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})

    numberMessage =
      :crypto.hash(hashfunc, message)
      |> BinaryAscii.numberFromString()

    curve = publicKey.curve

    inv = Math.inv(signature.s, curve."N")

    signature.r ==
      Math.add(
        Math.multiply(
          curve."G",
          IntegerUtils.modulo(numberMessage * inv, curve."N"),
          curve."A",
          curve."P",
          curve."N"
        ),
        Math.multiply(
          publicKey.point,
          IntegerUtils.modulo(signature.r * inv, curve."N"),
          curve."A",
          curve."P",
          curve."N"
        ),
        curve."P",
        curve."A"
      ).x
  end
end
