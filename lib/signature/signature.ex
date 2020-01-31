defmodule EllipticCurve.Signature do
  @moduledoc """
  Used to convert signature between struct (raw numbers r and s) and der or pem formats

  Functions:
  - fromBase64()
  - fromBase64!()
  - fromDer()
  - fromDer!()
  - toBase64()
  - toDer()
  """

  alias EllipticCurve.Signature.Data, as: Data
  alias EllipticCurve.Utils.{Der, Base64, BinaryAscii}

  @doc """
  Converts a base 64 signature into the decoded struct format

  Parameters:
  - base64 [string]: message that will be signed

  Returns {:ok, signature}:
  - signature [EllipticCurve.Signature.Data]: decoded signature, exposing r and s;

  ## Example:

      iex> EllipticCurve.Ecdsa.fromBase64("YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE=")
      {:ok, %EllipticCurve.Signature.Data{r: 123, s: 456}}
  """
  def fromBase64(base64) do
    {:ok, fromBase64(base64)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc """
  Converts a base 64 signature into the decoded struct format

  Parameters:
  - base64 [string]: signature in base 64 format

  Returns {:ok, signature}:
  - signature [EllipticCurve.Signature.Data]: decoded signature, exposing r and s;

  ## Example:

      iex> EllipticCurve.Ecdsa.fromBase64!("YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE=")
      %EllipticCurve.Signature.Data{r: 123, s: 456}
  """
  def fromBase64!(base64String) do
    base64String
    |> Base64.decode()
    |> fromDer()
  end

  @doc """
  Converts a der signature (raw binary) into the decoded struct format

  Parameters:
  - der [string]: signature in der format (raw binary)

  Returns {:ok, signature}:
  - signature [EllipticCurve.Signature.Data]: decoded signature, exposing r and s;

  ## Example:

      iex> EllipticCurve.Ecdsa.fromDer("  ˜813981 ùu1i3 i")
      {:ok, %EllipticCurve.Signature.Data{r: 123, s: 456}}
  """
  def fromDer(der) do
    {:ok, fromDer!(der)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc """
  Converts a der signature (raw binary) into the decoded struct format

  Parameters:
  - der [string]: signature in der format (raw binary)

  Returns {:ok, signature}:
  - signature [EllipticCurve.Signature.Data]: decoded signature, exposing r and s;

  ## Example:

      iex> EllipticCurve.Ecdsa.fromDer!("  ˜813981 ùu1i3 i")
      %EllipticCurve.Signature.Data{r: 123, s: 456}
  """
  def fromDer!(der) do
    {rs, firstEmpty} = Der.removeSequence(string)

    if length(firstEmpty) > 0 do
      raise "trailing junk after DER signature: " <> BinaryAscii.hexFromBinary(firstEmpty)
    end

    {r, rest} = Der.removeInteger(rs)
    {s, secondEmpty} = Der.removeInteger(rest)

    if length(secondEmpty) > 0 do
      raise "trailing junk after DER numbers: " <> BinaryAscii.hexFromBinary(secondEmpty)
    end

    %Data{r: r, s: s}
  end

  @doc """
  Converts a signature in decoded struct format into a base 64 string

  Parameters:
  - signature [EllipticCurve.Signature.Data]: decoded signature struct;

  Returns {:ok, base64}:
  - base64 [string]: signature in base 64 format

  ## Example:

      iex> EllipticCurve.Ecdsa.toBase64(%EllipticCurve.Signature.Data{r: 123, s: 456})
      {:ok, "YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE="}
  """
  def toBase64(signature) do
    signature
    |> toDer()
    |> Base64.encode()
  end

  @doc """
  Converts a signature in decoded struct format into der format (raw binary)

  Parameters:
  - signature [EllipticCurve.Signature.Data]: decoded signature struct;

  Returns {:ok, der}:
  - der [string]: signature in der format

  ## Example:

      iex> EllipticCurve.Ecdsa.toDer(%EllipticCurve.Signature.Data{r: 123, s: 456})
      {:ok, "  ˜813981 ùu1i3 i"}
  """
  def toDer(signature) do
    Der.encodeSequence(
      Der.encodeInteger(signature.r),
      Der.encodeInteger(signature.s)
    )
  end
end
