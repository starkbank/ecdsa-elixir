defmodule EllipticCurve.PublicKey do
  @moduledoc """
  Used to convert public keys between struct and .der or .pem formats.
  Supports compressed public key format.
  """

  alias __MODULE__, as: PublicKey
  alias EllipticCurve.Utils.{Der, BinaryAscii}
  alias EllipticCurve.{Point, Curve, Math}

  defstruct [:point, :curve]

  @evenTag "02"
  @oddTag "03"

  @doc """
  Converts a public key in decoded struct format into a pem string.
  """
  def toPem(publicKey) do
    publicKey
    |> toDer()
    |> Der.toPem("PUBLIC KEY")
  end

  @doc """
  Converts a public key in decoded struct format into a der string (raw binary).
  """
  def toDer(publicKey) do
    Der.encodeSequence([
      Der.encodeSequence([
        Der.encodeOid([1, 2, 840, 10045, 2, 1]),
        Der.encodeOid(publicKey.curve.oid)
      ]),
      Der.encodeBitString(toString(publicKey, true))
    ])
  end

  @doc false
  def toString(publicKey, encoded \\ false) do
    curveLength = Curve.getLength(publicKey.curve)

    xString =
      BinaryAscii.stringFromNumber(
        publicKey.point.x,
        curveLength
      )

    yString =
      BinaryAscii.stringFromNumber(
        publicKey.point.y,
        curveLength
      )

    if encoded do
      "\x00\x04" <> xString <> yString
    else
      xString <> yString
    end
  end

  @doc """
  Converts the public key to compressed hex string format.
  """
  def toCompressed(publicKey) do
    baseLength = 2 * Curve.getLength(publicKey.curve)
    parityTag = if rem(publicKey.point.y, 2) == 0, do: @evenTag, else: @oddTag
    xHex = Integer.to_string(publicKey.point.x, 16)
            |> String.downcase()
            |> String.pad_leading(baseLength, "0")
    parityTag <> xHex
  end

  @doc """
  Converts a public key in pem format into decoded struct format.
  """
  def fromPem(pem) do
    {:ok, fromPem!(pem)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  def fromPem!(pem) do
    pem
    |> Der.fromPem()
    |> fromDer!()
  end

  def fromDer(der) do
    {:ok, fromDer!(der)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  def fromDer!(der) do
    {s1, empty} = Der.removeSequence(der)

    if byte_size(empty) != 0 do
      raise "trailing junk after DER public key: #{BinaryAscii.hexFromBinary(empty)}"
    end

    {s2, pointBitString} = Der.removeSequence(s1)

    {_oidPublicKey, rest} = Der.removeObject(s2)

    {oidCurve, empty} = Der.removeObject(rest)

    if byte_size(empty) != 0 do
      raise "trailing junk after DER public key objects: #{BinaryAscii.hexFromBinary(empty)}"
    end

    curve = Curve.KnownCurves.getCurveByOid(oidCurve)

    {pointString, empty} = Der.removeBitString(pointBitString)

    if byte_size(empty) != 0 do
      raise "trailing junk after public key point-string: #{BinaryAscii.hexFromBinary(empty)}"
    end

    binary_part(pointString, 2, byte_size(pointString) - 2)
    |> fromString!(curve)
  end

  @doc false
  def fromString(string, curve \\ :secp256k1, validatePoint \\ true) do
    {:ok, fromString!(string, curve, validatePoint)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc false
  def fromString!(string, curve \\ :secp256k1, validatePoint \\ true) do
    curve = resolve_curve(curve)
    baseLength = Curve.getLength(curve)

    xs = binary_part(string, 0, baseLength)
    ys = binary_part(string, baseLength, byte_size(string) - baseLength)

    point = %Point{
      x: BinaryAscii.numberFromString(xs),
      y: BinaryAscii.numberFromString(ys)
    }

    publicKey = %PublicKey{point: point, curve: curve}

    cond do
      validatePoint == false -> publicKey
      Point.isAtInfinity?(point) ->
        raise "Public Key point is at infinity"
      Curve.contains?(curve, point) == false ->
        raise "Point (#{point.x},#{point.y}) is not valid for curve #{curve.name}"
      Point.isAtInfinity?(Math.multiply(point, curve."N", curve."N", curve."A", curve."P")) == false ->
        raise "Point (#{point.x},#{point.y}) * #{curve.name}.N is not at infinity"
      true -> publicKey
    end
  end

  @doc """
  Recover a public key from a compressed hex string.
  """
  def fromCompressed(string, curve \\ :secp256k1) do
    curve = resolve_curve(curve)
    parityTag = String.slice(string, 0, 2)
    xHex = String.slice(string, 2..-1//1)

    if parityTag not in [@evenTag, @oddTag] do
      raise "Compressed string should start with 02 or 03"
    end

    x = String.to_integer(xHex, 16)
    y = Curve.y(curve, x, parityTag == @evenTag)

    %PublicKey{point: %Point{x: x, y: y}, curve: curve}
  end

  defp resolve_curve(%Curve{} = curve), do: curve
  defp resolve_curve(name), do: Curve.KnownCurves.getCurveByName(name)
end
