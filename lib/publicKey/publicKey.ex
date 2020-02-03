defmodule EllipticCurve.PublicKey do
  @moduledoc """
  Used to convert public keys between struct and der or pem formats

  Functions:
  - toPem()
  - toDer()
  - fromPem()
  - fromPem!()
  - fromDer()
  - fromDer!()
  """

  alias EllipticCurve.Utils.{Der, Base64, BinaryAscii, Point}
  alias EllipticCurve.{Curve}
  alias EllipticCurve.PublicKey.{Data}

  @doc """
  Converts a public key in decoded struct format into a pem string

  Parameters:
  - publicKey [EllipticCurve.PublicKey.Data]: decoded public key struct;

  Returns {:ok, pem}:
  - pem [string]: public key in pem format

  ## Example:

      iex> EllipticCurve.PublicKey.toPem(%EllipticCurve.PublicKey.Data{...})
      {:ok, "YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE="}
  """
  def toPem(publicKey) do
    Der.toPem(toDer(publicKey), "PUBLIC KEY")
  end

  @doc """
  Converts a public key in decoded struct format into a der string (raw binary)

  Parameters:
  - publicKey [EllipticCurve.PublicKey.Data]: decoded public key struct;

  Returns {:ok, der}:
  - der [string]: public key in der format

  ## Example:

      iex> EllipticCurve.PublicKey.toDer(%EllipticCurve.PublicKey.Data{...})
      {:ok, "  1 ó~  ia "}
  """
  def toDer(publicKey) do
    Der.encodeSequence(
      Der.encodeSequence(
        Der.encodeOid({1, 2, 840, 10045, 2, 1}),
        Der.encodeOid(publicKey.curve.oid)
      ),
      Der.encodeBitString(toString(publicKey, true))
    )
  end

  defp toString(publicKey, encoded) do
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

  Returns {:ok, der}:
  - publicKey [EllipticCurve.PublicKey.Data]: decoded public key struct;

  ## Example:

      iex> EllipticCurve.PublicKey.fromPem("YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE=")
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

  Returns {:ok, der}:
  - publicKey [EllipticCurve.PublicKey.Data]: decoded public key struct;

  ## Example:

      iex> EllipticCurve.PublicKey.fromPem!("YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE=")
      %EllipticCurve.PublicKey.Data{...}
  """
  def fromPem!(pem) do
    Der.fromPem(pem)
    |> fromDer()
  end

  @doc """
  Converts a public key in der (raw binary) format into decoded struct format

  Parameters:
  - der [string]: public key in der format

  Returns {:ok, der}:
  - publicKey [EllipticCurve.PublicKey.Data]: decoded public key struct;

  ## Example:

      iex> EllipticCurve.PublicKey.fromDer("  1 ó~  ia ")
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

  Returns {:ok, der}:
  - publicKey [EllipticCurve.PublicKey.Data]: decoded public key struct;

  ## Example:

      iex> EllipticCurve.PublicKey.fromDer!("  1 ó~  ia ")
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

    curve = Curve.KnownCurves.getCurveByOid(oidCurve)

    {pointString, empty} = Der.removeBitString(pointBitString)

    if byte_size(empty) != 0 do
      raise "trailing junk after public key point-string: #{BinaryAscii.hexFromBinary(empty)}"
    end

    fromString(String.slice(pointString, 2, byte_size(pointString) - 2), curve)
  end

  defp fromString(string, curve, validatePoint \\ true) do
    curveData = Curve.KnownCurves.getCurveByName(curve)
    baseLength = Curve.getLength(curveData)

    xs = String.slice(string, 0, baseLength)
    ys = String.slice(string, baseLength, byte_size(string))

    point = %Point{
      x: BinaryAscii.numberFromString(xs),
      y: BinaryAscii.numberFromString(ys)
    }

    if validatePoint and !curve.contains?(point) do
      raise "point (#{point.x}, #{point.y}) is not valid for curve #{curveData.name}"
    end

    %Data{point: point, curve: curve}
  end
end
