defmodule EllipticCurve.PrivateKey do
  @moduledoc """
  Used to create private keys or convert them between struct and .der or .pem formats.
  Also allows creation of public keys from private keys.
  """

  alias __MODULE__, as: PrivateKey
  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Utils.{Der, BinaryAscii}
  alias EllipticCurve.{PublicKey, Curve, Math}

  defstruct [:secret, :curve]

  @hexAt "\x00"

  @doc """
  Creates a new private key.

  Accepts:
  - `generate()` - random key on secp256k1
  - `generate(secret)` - key with given secret on secp256k1
  - `generate(secret, curve)` - key with given secret on given curve (atom name or %Curve{})
  """
  def generate(secret \\ nil, curve \\ :secp256k1)

  def generate(secret, curve) when is_nil(secret) do
    resolved = resolve_curve(curve)

    generate(
      IntegerUtils.between(1, resolved."N" - 1),
      resolved
    )
  end

  def generate(secret, %Curve{} = curve) do
    %PrivateKey{
      secret: secret,
      curve: curve
    }
  end

  def generate(secret, curve) do
    %PrivateKey{
      secret: secret,
      curve: resolve_curve(curve)
    }
  end

  @doc """
  Gets the public key associated with a private key.
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
  Converts a private key in decoded struct format into a pem string.
  """
  def toPem(privateKey) do
    Der.toPem(
      toDer(privateKey),
      "EC PRIVATE KEY"
    )
  end

  @doc """
  Converts a private key in decoded struct format into a der string (raw binary).
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
  Converts a private key in pem format into decoded struct format.
  """
  def fromPem(pem) do
    {:ok, fromPem!(pem)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  def fromPem!(pem) do
    String.split(pem, "-----BEGIN EC PRIVATE KEY-----")
    |> List.last()
    |> Der.fromPem()
    |> fromDer!
  end

  def fromDer(der) do
    {:ok, fromDer!(der)}
  rescue
    e in RuntimeError -> {:error, e}
  end

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
      |> fromString!(curve)
    else
      fromString!(privateKeyString, curve)
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
      curve: resolve_curve(curve)
    }
  end

  defp resolve_curve(%Curve{} = curve), do: curve
  defp resolve_curve(name), do: Curve.KnownCurves.getCurveByName(name)
end
