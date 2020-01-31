defmodule EllipticCurve.PrivateKey do
  @moduledoc """
  Used to convert private key between struct and der or pem formats

  Functions:
  - generate()
  - toPem()
  - toDer()
  - fromPem()
  - fromPem!()
  - fromDer()
  - fromDer!()
  """

  alias EllipticCurve.{Curve}
  alias EllipticCurve.PrivateKey.{Data}
  alias EllipticCurve.PublicKey.Data, as: PublicKeyData
  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Utils.{Der, Base64, BinaryAscii, Point}

  @hexAt "\x00"

  @doc """
  Creates a new private key

  Parameters:
  - secret [int]: private key secret (default nil: random key will be generated)
  - curve [atom]: curve name (default :secp256k1)

  Returns {:ok, privateKey}:
  - privateKey [EllipticCurve.PrivateKey.Data]: private key struct

  ## Example:

      iex> EllipticCurve.PrivateKey.generate()
      %EllipticCurve.PrivateKey.Data{...}
  """
  def generate(secret: nil, curve: :secp256k1)

  def generate(secret, curve) when is_nil(secret) do
    generate(
      IntegerUtils.between(
        1,
        Curve.getCurveByName(:secp256k1).N - 1
      ),
      curve
    )
  end

  def generate(secret, curve) do
    %Data{
      secret: secret,
      curve: Curve.getCurveByName(:secp256k1)
    }
  end

  @doc """
  Gets the public associated with a private key

  Parameters:
  - privateKey [int]: private key secret (default nil: random key will be generated)

  Returns {:ok, publicKey}:
  - publicKey [EllipticCurve.PublicKey.Data]: public key struct

  ## Example:

      iex> EllipticCurve.PrivateKey.getPublicKey(privateKey)
      %EllipticCurve.PublicKey.Data{...}
  """
  def getPublicKey(privateKey) do
    curveData = privateKey.curve

    %PublicKeyData{
      point:
        Math.multiply(
          curveData.G,
          privateKey.secret,
          curveData.N,
          curveData.A,
          curveData.P
        ),
      curve: curveData
    }
  end

  @doc """
  Converts a private key in decoded struct format into a pem string

  Parameters:
  - privateKey [EllipticCurve.PrivateKey.Data]: decoded private key struct;

  Returns {:ok, pem}:
  - pem [string]: private key in pem format

  ## Example:

      iex> EllipticCurve.PrivateKey.toPem(%EllipticCurve.PrivateKey.Data{...})
      {:ok, "YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE="}
  """
  def toPem(privateKey) do
    Der.toPem(
      toDer(privateKey),
      "EC PRIVATE KEY"
    )
  end

  @doc """
  Converts a private key in decoded struct format into a der string (raw binary)

  Parameters:
  - privateKey [EllipticCurve.PrivateKey.Data]: decoded private key struct;

  Returns {:ok, der}:
  - der [string]: private key in der format

  ## Example:

      iex> EllipticCurve.PrivateKey.toDer(%EllipticCurve.PrivateKey.Data{...})
      {:ok, "    ó^ad  12 "}
  """
  def toDer(privateKey) do
    Der.encodeSequence(
      Der.encodeInteger(1),
      Der.encodeOctetString(toString(privateKey)),
      Der.encodeConstructed(0, encodeOid(privateKey.curve.oid)),
      Der.encodeConstructed(
        1,
        encodeBitString(PublicKey.toString(getPublicKey(privateKey), true))
      )
    )
  end

  defp toString(privateKey) do
    BinaryAscii.stringFromNumber(privateKey.secret, Curve.getLength(privateKey.curve))
  end

  @doc """
  Converts a private key in pem format into decoded struct format

  Parameters:
  - pem [string]: private key in pem format

  Returns {:ok, der}:
  - privateKey [EllipticCurve.PrivateKey.Data]: decoded private key struct;

  ## Example:

      iex> EllipticCurve.PrivateKey.fromPem("YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE=")
      {:ok, %EllipticCurve.PrivateKey.Data{...}}
  """
  def fromPem(pem) do
    {:ok, fromPem!(pem)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc """
  Converts a private key in pem format into decoded struct format

  Parameters:
  - pem [string]: private key in pem format

  Returns {:ok, der}:
  - privateKey [EllipticCurve.PrivateKey.Data]: decoded private key struct;

  ## Example:

      iex> EllipticCurve.PrivateKey.fromPem!("YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE=")
      %EllipticCurve.PrivateKey.Data{...}
  """
  def fromPem!(pem) do
    String.split(pem, "-----BEGIN EC PRIVATE KEY-----")
    |> List.last()
    |> Der.fromPem()
    |> fromDer
  end

  @doc """
  Converts a private key in der format into decoded struct format

  Parameters:
  - der [string]: private key in der format

  Returns {:ok, der}:
  - privateKey [EllipticCurve.PrivateKey.Data]: decoded private key struct;

  ## Example:

      iex> EllipticCurve.PrivateKey.fromDer("    óa das 1 ")
      {:ok, %EllipticCurve.PrivateKey.Data{...}}
  """
  def fromDer(der) do
    {:ok, fromDer!(der)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc """
  Converts a private key in der format into decoded struct format

  Parameters:
  - der [string]: private key in der format

  Returns {:ok, der}:
  - privateKey [EllipticCurve.PrivateKey.Data]: decoded private key struct;

  ## Example:

      iex> EllipticCurve.PrivateKey.fromDer!("    óa das 1 ")
      %EllipticCurve.PrivateKey.Data{...}
  """
  def fromDer!(der) do
    {bytes1, empty} = Der.removeSequence(der)

    if lenght(empty) != 0 do
      raise "trailing junk after DER private key: #{BinaryAscii.hexFromBinary(empty)}"
    end

    {one, bytes2} = removeInteger(bytes1)

    if one != 1 do
      raise "expected '1' at start of DER private key, got #{one}"
    end

    {privateKeyString, bytes3} = Der.removeOctetString(bytes2)
    {tag, curveOidString, _bytes4} = Der.removeConstructed(bytes3)

    if tag != 0 do
      raise "expected tag 0 in DER private key, got #{tag}"
    end

    {oidCurve, empty} = Der.removeObject(curveOidString)

    if len(empty) != 0 do
      raise "trailing junk after DER private key curve_oid: #{BinaryAscii.hexFromBinary(empty)}"
    end

    privateKeyStringLength = String.length(privateKeyString)
    curveData = Curve.getCurveByOid(oidCurve)
    curveLength = Curve.getLength(curveData)

    if privateKeyStringLength < curveLength do
      (String.duplicate(@hexAt, curveLength - privateKeyStringLength) <> privateKeyStr)
      |> fromString(curveData)
    else
      fromString(privateKeyStr, curveData)
    end
  end

  defp fromString(string, curveData) do
    %Data{
      secret: BinaryAscii.numberFromString(string),
      curve: curveData
    }
  end
end
