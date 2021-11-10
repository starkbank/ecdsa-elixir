defmodule EllipticCurve.Ecdsa do
  @moduledoc """
  Used to sign and verify signatures using the Elliptic Curve Digital Signature Algorithm (ECDSA)

  Functions:
  - sign()
  - verify?()
  """

  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Utils.BinaryAscii
  alias EllipticCurve.{Point, Signature, Math}

  @doc """
  Generates a message signature based on a private key

  Parameters:
  - message [string]: message that will be signed
  - privateKey [%EllipticCurve.PrivateKey]: private key data associated with the signer
  - options [keyword list]: refines request
    - hashfunc [:method]: defines the hash function applied to the message. Must be compatible with :crypto.hash. Default: :sha256;

  Returns signature:
  - signature [string]: base-64 message signature;

  ## Example:

      iex> EllipticCurve.Ecdsa.sign("my message", privateKey)
      "MEQCIFp2TrQ6RlThbEOeYin2t+Dz3TAebeK/kinZaU0Iltm4AiBXyvyCTwgjOBo5eZNssw/3shTqn8eHZyoRiToSttrRFw=="
  """
  def sign(message, privateKey, options \\ []) do
    %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})

    numberMessage =
      :crypto.hash(hashfunc, message)
      |> BinaryAscii.numberFromString()

    curveData = privateKey.curve

    randNum = IntegerUtils.between(1, curveData."N" - 1)

    r =
      Math.multiply(curveData."G", randNum, curveData."N", curveData."A", curveData."P").x
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
  - signature [%EllipticCurve.Signature]: signature associated with the message
  - publicKey [%EllipticCurve.PublicKey]: public key associated with the message signer
  - options [keyword list]: refines request
    - hashfunc [:method]: defines the hash function applied to the message. Must be compatible with :crypto.hash. Default: :sha256;

  Returns:
  - verified [bool]: true if message, public key and signature are compatible, false otherwise;

  ## Example:

      iex> EllipticCurve.Ecdsa.verify?(message, signature, publicKey)
      true
      iex> EllipticCurve.Ecdsa.verify?(wrongMessage, signature, publicKey)
      false
      iex> EllipticCurve.Ecdsa.verify?(message, wrongSignature, publicKey)
      false
      iex> EllipticCurve.Ecdsa.verify?(message, signature, wrongPublicKey)
      false
  """
  def verify?(message, signature, publicKey, options \\ []) do
    %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})

    numberMessage =
      :crypto.hash(hashfunc, message)
      |> BinaryAscii.numberFromString()

    curveData = publicKey.curve

    inv = Math.inv(signature.s, curveData."N")

    v = Math.add(
      Math.multiply(
        curveData."G",
        IntegerUtils.modulo(numberMessage * inv, curveData."N"),
        curveData."N",
        curveData."A",
        curveData."P"
      ),
      Math.multiply(
        publicKey.point,
        IntegerUtils.modulo(signature.r * inv, curveData."N"),
        curveData."N",
        curveData."A",
        curveData."P"
      ),
      curveData."A",
      curveData."P"
    )

    cond do
      signature.r < 1 || signature.r >= curveData."N" -> false
      signature.s < 1 || signature.s >= curveData."N" -> false
      Point.isAtInfinity?(v) -> false
      IntegerUtils.modulo(v.x, curveData."N") != signature.r -> false
      true -> true
    end
  end
end
