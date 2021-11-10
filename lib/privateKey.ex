defmodule EllipticCurve.PrivateKey do
  @moduledoc """
  Used to create private keys or convert them between struct and .der or .pem formats. Also allows creations of public keys from private keys.

  Functions:
  - generate()
  - toPem()
  - toDer()
  - fromPem()
  - fromPem!()
  - fromDer()
  - fromDer!()
  """

  alias __MODULE__, as: PrivateKey
  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Utils.{Der, BinaryAscii}
  alias EllipticCurve.{PublicKey, Curve, Math}

  @doc """
  Holds private key data. Is usually extracted from .pem files.

  Parameters:
  - `:secret` [integer]: private key secret number;
  - `:curve` [%EllipticCurve.Curve]: private key curve information;
  """
  defstruct [:secret, :curve]

  @hexAt "\x00"

  @doc """
  Creates a new private key

  Parameters:
  - `secret` [integer]: private key secret; Default: nil -> random key will be generated;
  - `curve` [atom]: curve name; Default: :secp256k1;

  Returns:
  - `privateKey` [%EllipticCurve.PrivateKey]: private key struct

  ## Example:

      iex> EllipticCurve.PrivateKey.generate()
      %EllipticCurve.PrivateKey{...}
  """
  def generate(secret \\ nil, curve \\ :secp256k1)

  def generate(secret, curve) when is_nil(secret) do
    generate(
      IntegerUtils.between(
        1,
        Curve.KnownCurves.getCurveByName(curve)."N" - 1
      ),
      curve
    )
  end

  def generate(secret, curve) do
    %PrivateKey{
      secret: secret,
      curve: Curve.KnownCurves.getCurveByName(curve)
    }
  end

  @doc """
  Gets the public associated with a private key

  Parameters:
  - `privateKey` [%EllipticCurve.PrivateKey]: private key struct

  Returns:
  - `publicKey` [%EllipticCurve.PublicKey]: public key struct

  ## Example:

      iex> EllipticCurve.PrivateKey.getPublicKey(privateKey)
      %EllipticCurve.PublicKey{...}
  """
  def getPublicKey(privateKey) do
    curve = privateKey.curve
    %PublicKey{
      point:
        Math.multiply(
          curve."G",
          privateKey.secret,
          curve."N",
          curve."A",
          curve."P"
        ),
      curve: curve
    }
  end

  @doc """
  Converts a private key in decoded struct format into a pem string

  Parameters:
  - `privateKey` [%EllipticCurve.PrivateKey]: decoded private key struct;

  Returns:
  - `pem` [string]: private key in pem format

  ## Example:

      iex> EllipticCurve.PrivateKey.toPem(%EllipticCurve.PrivateKey{...})
      "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIDvS/RddF6iYa/q4oVSrGa3Kbd7aSooNpwhv9puJVv1loAcGBSuBBAAK\noUQDQgAErp2I78X4cqHscCRWMT4rhouyO197iQXRfdGgsgfS/UGaIviYiqnG3SSa\n9dsOHU/NkVSTLkBPCI0RQLF3554dZg==\n-----END EC PRIVATE KEY-----\n"
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
  - `privateKey` [$EllipticCurve.PrivateKey]: decoded private key struct;

  Returns:
  - `der` [string]: private key in der format

  ## Example:

      iex> EllipticCurve.PrivateKey.toDer(%EllipticCurve.PrivateKey{...})
      <<48, 116, 2, 1, 1, 4, 32, 59, 210, 253, 23, 93, 23, ...>>
  """
  def toDer(privateKey) do
    Der.encodeSequence([
      Der.encodeInteger(1),
      Der.encodeOctetString(toString(privateKey)),
      Der.encodeConstructed(0, Der.encodeOid(privateKey.curve.oid)),
      Der.encodeConstructed(
        1,
        Der.encodeBitString(PublicKey.toString(getPublicKey(privateKey), true))
      )
    ])
  end

  @doc false
  def toString(privateKey) do
    BinaryAscii.stringFromNumber(privateKey.secret, Curve.getLength(privateKey.curve))
  end

  @doc """
  Converts a private key in pem format into decoded struct format

  Parameters:
  - `pem` [string]: private key in pem format

  Returns {:ok, privateKey}:
  - `privateKey` [%EllipticCurve.PrivateKey]: decoded private key struct;

  ## Example:

      iex> EllipticCurve.PrivateKey.fromPem("-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIDvS/RddF6iYa/q4oVSrGa3Kbd7aSooNpwhv9puJVv1loAcGBSuBBAAK\noUQDQgAErp2I78X4cqHscCRWMT4rhouyO197iQXRfdGgsgfS/UGaIviYiqnG3SSa\n9dsOHU/NkVSTLkBPCI0RQLF3554dZg==\n-----END EC PRIVATE KEY-----\n")
      {:ok, %EllipticCurve.PrivateKey{...}}
  """
  def fromPem(pem) do
    {:ok, fromPem!(pem)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc """
  Converts a private key in pem format into decoded struct format

  Parameters:
  - `pem` [string]: private key in pem format

  Returns:
  - `privateKey` [%EllipticCurve.PrivateKey]: decoded private key struct;

  ## Example:

      iex> EllipticCurve.PrivateKey.fromPem!("-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIDvS/RddF6iYa/q4oVSrGa3Kbd7aSooNpwhv9puJVv1loAcGBSuBBAAK\noUQDQgAErp2I78X4cqHscCRWMT4rhouyO197iQXRfdGgsgfS/UGaIviYiqnG3SSa\n9dsOHU/NkVSTLkBPCI0RQLF3554dZg==\n-----END EC PRIVATE KEY-----\n")
      %EllipticCurve.PrivateKey{...}
  """
  def fromPem!(pem) do
    String.split(pem, "-----BEGIN EC PRIVATE KEY-----")
    |> List.last()
    |> Der.fromPem()
    |> fromDer!
  end

  @doc """
  Converts a private key in der format into decoded struct format

  Parameters:
  - `der` [string]: private key in der format

  Returns {:ok, privateKey}:
  - `privateKey` [%EllipticCurve.PrivateKey]: decoded private key struct;

  ## Example:

      iex> EllipticCurve.PrivateKey.fromDer(<<48, 116, 2, 1, 1, 4, 32, 59, 210, 253, 23, 93, 23, ...>>)
      {:ok, %EllipticCurve.PrivateKey{...}}
  """
  def fromDer(der) do
    {:ok, fromDer!(der)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc """
  Converts a private key in der format into decoded struct format

  Parameters:
  - `der` [string]: private key in der format

  Returns:
  - `privateKey` [%EllipticCurve.PrivateKey]: decoded private key struct;

  ## Example:

      iex> EllipticCurve.PrivateKey.fromDer!(<<48, 116, 2, 1, 1, 4, 32, 59, 210, 253, 23, 93, 23, ...>>)
      %EllipticCurve.PrivateKey{...}
  """
  def fromDer!(der) do
    {bytes1, empty} = Der.removeSequence(der)

    if byte_size(empty) != 0 do
      throw("trailing junk after DER private key: #{BinaryAscii.hexFromBinary(empty)}")
    end

    {one, bytes2} = Der.removeInteger(bytes1)

    if one != 1 do
      throw("expected '1' at start of DER private key, got #{one}")
    end

    {privateKeyString, bytes3} = Der.removeOctetString(bytes2)
    {tag, curveOidString, _bytes4} = Der.removeConstructed(bytes3)

    if tag != 0 do
      throw("expected tag 0 in DER private key, got #{tag}")
    end

    {oidCurve, empty} = Der.removeObject(curveOidString)

    if byte_size(empty) != 0 do
      throw("trailing junk after DER private key curve_oid: #{BinaryAscii.hexFromBinary(empty)}")
    end

    privateKeyStringLength = byte_size(privateKeyString)
    curve = Curve.KnownCurves.getCurveByOid(oidCurve)
    curveLength = Curve.getLength(curve)

    if privateKeyStringLength < curveLength do
      (String.duplicate(@hexAt, curveLength - privateKeyStringLength) <> privateKeyString)
      |> fromString(curve)
    else
      fromString!(privateKeyString, curve.name)
    end
  end

  @doc false
  def fromString(string, curve \\ :secp256k1) do
    {:ok, fromString!(string, curve)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc false
  def fromString!(string, curve \\ :secp256k1) do
    %PrivateKey{
      secret: BinaryAscii.numberFromString(string),
      curve: Curve.KnownCurves.getCurveByName(curve)
    }
  end
end
