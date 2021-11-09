defmodule EllipticCurve.PublicKey do
  @moduledoc """
  Used to convert public keys between struct and .der or .pem formats.

  Functions:
  - toPem()
  - toDer()
  - fromPem()
  - fromPem!()
  - fromDer()
  - fromDer!()
  """

  alias EllipticCurve.Utils.{Der, BinaryAscii, Math}
  alias EllipticCurve.Utils.Point
  alias EllipticCurve.Utils.Point.Data, as: PointData
  alias EllipticCurve.{Curve}
  alias EllipticCurve.PublicKey.{Data}

  @doc """
  Converts a public key in decoded struct format into a pem string

  Parameters:
  - publicKey [%EllipticCurve.PublicKey.Data]: decoded public key struct;

  Returns:
  - pem [string]: public key in pem format

  ## Example:

      iex> EllipticCurve.PublicKey.toPem(%EllipticCurve.PublicKey.Data{...})
      "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAErp2I78X4cqHscCRWMT4rhouyO197iQXR\nfdGgsgfS/UGaIviYiqnG3SSa9dsOHU/NkVSTLkBPCI0RQLF3554dZg==\n-----END PUBLIC KEY-----\n"
  """
  def toPem(publicKey) do
    publicKey
    |> toDer()
    |> Der.toPem("PUBLIC KEY")
  end

  @doc """
  Converts a public key in decoded struct format into a der string (raw binary)

  Parameters:
  - publicKey [%EllipticCurve.PublicKey.Data]: decoded public key struct;

  Returns:
  - der [string]: public key in der format

  ## Example:

      iex> EllipticCurve.PublicKey.toDer(%EllipticCurve.PublicKey.Data{...})
      <<48, 86, 48, 16, 6, 7, 42, 134, 72, 206, 61, ...>>
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
  Converts a public key in pem format into decoded struct format

  Parameters:
  - pem [string]: public key in pem format

  Returns {:ok, publicKey}:
  - publicKey [%EllipticCurve.PublicKey.Data]: decoded public key struct;

  ## Example:

      iex> EllipticCurve.PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAErp2I78X4cqHscCRWMT4rhouyO197iQXR\nfdGgsgfS/UGaIviYiqnG3SSa9dsOHU/NkVSTLkBPCI0RQLF3554dZg==\n-----END PUBLIC KEY-----\n")
      {:ok, %EllipticCurve.PublicKey.Data{...}}
  """
  def fromPem(pem) do
    {:ok, fromPem!(pem)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc """
  Converts a public key in pem format into decoded struct format

  Parameters:
  - pem [string]: public key in pem format

  Returns:
  - publicKey [%EllipticCurve.PublicKey.Data]: decoded public key struct;

  ## Example:

      iex> EllipticCurve.PublicKey.fromPem!("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAErp2I78X4cqHscCRWMT4rhouyO197iQXR\nfdGgsgfS/UGaIviYiqnG3SSa9dsOHU/NkVSTLkBPCI0RQLF3554dZg==\n-----END PUBLIC KEY-----\n")
      %EllipticCurve.PublicKey.Data{...}
  """
  def fromPem!(pem) do
    pem
    |> Der.fromPem()
    |> fromDer!()
  end

  @doc """
  Converts a public key in der (raw binary) format into decoded struct format

  Parameters:
  - der [string]: public key in der format

  Returns {:ok, publicKey}:
  - publicKey [%EllipticCurve.PublicKey.Data]: decoded public key struct;

  ## Example:

      iex> EllipticCurve.PublicKey.fromDer(<<48, 86, 48, 16, 6, 7, 42, 134, ...>>)
      {:ok, %EllipticCurve.PublicKey.Data{...}}
  """
  def fromDer(der) do
    {:ok, fromDer!(der)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc """
  Converts a public key in der (raw binary) format into decoded struct format

  Parameters:
  - der [string]: public key in der format

  Returns:
  - publicKey [%EllipticCurve.PublicKey.Data]: decoded public key struct;

  ## Example:

      iex> EllipticCurve.PublicKey.fromDer!(<<48, 86, 48, 16, 6, 7, 42, 134, ...>>)
      %EllipticCurve.PublicKey.Data{...}
  """
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

    curveData = Curve.KnownCurves.getCurveByOid(oidCurve)

    {pointString, empty} = Der.removeBitString(pointBitString)

    if byte_size(empty) != 0 do
      raise "trailing junk after public key point-string: #{BinaryAscii.hexFromBinary(empty)}"
    end

    binary_part(pointString, 2, byte_size(pointString) - 2)
    |> fromString!(curveData.name)
  end

  @doc false
  def fromString(string, curve \\ :secp256k1, validatePoint \\ true) do
    {:ok, fromString!(string, curve, validatePoint)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc false
  def fromString!(string, curve \\ :secp256k1, validatePoint \\ true) do
    curveData = Curve.KnownCurves.getCurveByName(curve)
    baseLength = Curve.getLength(curveData)

    xs = binary_part(string, 0, baseLength)
    ys = binary_part(string, baseLength, byte_size(string) - baseLength)

    point = %PointData{
      x: BinaryAscii.numberFromString(xs),
      y: BinaryAscii.numberFromString(ys)
    }
    
    publicKey = %Data{point: point, curve: curveData}

    cond do
      validatePoint == false -> publicKey
      Point.isAtInfinity?(point) -> 
        raise "Public Key point is at infinity"
      Curve.contains?(curveData, point) == false -> 
        raise "Point (#{point.x},#{point.y}) is not valid for curve #{curveData.name}"
      Point.isAtInfinity?(Math.multiply(point, curveData."N", curveData."N", curveData."A", curveData."P")) == false ->
        raise "Point (#{point.x},#{point.y}) * #{curveData.name}.N is not at infinity"
      true -> publicKey
    end
  end
end
