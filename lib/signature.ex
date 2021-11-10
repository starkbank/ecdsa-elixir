defmodule EllipticCurve.Signature do
  @moduledoc """
  Used to convert signature between struct (raw numbers r and s) and .der or .pem formats.

  Functions:
  - fromBase64()
  - fromBase64!()
  - fromDer()
  - fromDer!()
  - toBase64()
  - toDer()
  """

  alias __MODULE__, as: Signature
  alias EllipticCurve.Utils.{Der, Base64, BinaryAscii}

  @doc """
  Holds signature data. Is usually extracted from base64 strings.

  Parameters:
  - r [integer]: first signature number;
  - s [integer]: second signature number;
  """
  defstruct [:r, :s]

  @doc """
  Converts a base 64 signature into the decoded struct format

  Parameters:
  - base64 [string]: message that will be signed

  Returns {:ok, signature}:
  - signature [%EllipticCurve.Signature]: decoded signature, exposing r and s;

  ## Example:

      iex> EllipticCurve.Ecdsa.fromBase64("MEYCIQD861pJq/fZE7GnDBycwAbb3YglVoSCVub6TwMkgFS0NgIhAJCEZTh1Mlp1cWCgMXABqh9nOQznEXnhGoSYmZK6T99T")
      {:ok, %EllipticCurve.Signature{r: 114398670046563728651181765316495176217036114587592994448444521545026466264118, s: 65366972607021398158454632864220554542282541376523937745916477386966386597715}}
  """
  def fromBase64(base64) do
    {:ok, fromBase64!(base64)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc """
  Converts a base 64 signature into the decoded struct format

  Parameters:
  - base64 [string]: signature in base 64 format

  Returns {:ok, signature}:
  - signature [%EllipticCurve.Signature]: decoded signature, exposing r and s;

  ## Example:

      iex> EllipticCurve.Ecdsa.fromBase64!("MEYCIQD861pJq/fZE7GnDBycwAbb3YglVoSCVub6TwMkgFS0NgIhAJCEZTh1Mlp1cWCgMXABqh9nOQznEXnhGoSYmZK6T99T")
      %EllipticCurve.Signature{r: 114398670046563728651181765316495176217036114587592994448444521545026466264118, s: 65366972607021398158454632864220554542282541376523937745916477386966386597715}
  """
  def fromBase64!(base64String) do
    base64String
    |> Base64.decode()
    |> fromDer!()
  end

  @doc """
  Converts a der signature (raw binary) into the decoded struct format

  Parameters:
  - der [string]: signature in der format (raw binary)

  Returns {:ok, signature}:
  - signature [%EllipticCurve.Signature]: decoded signature, exposing r and s;

  ## Example:

      iex> EllipticCurve.Ecdsa.fromDer(<<48, 69, 2, 33, 0, 211, 243, 12, 93, ...>>)
      {:ok, %EllipticCurve.Signature{r: 95867440227398247533351136059968563162267771464707645727187625451839377520639, s: 35965164910442916948460815891253401171705649249124379540577916592403246631835}}
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

  Returns:
  - signature [%EllipticCurve.Signature]: decoded signature, exposing r and s;

  ## Example:

      iex> EllipticCurve.Ecdsa.fromDer!(<<48, 69, 2, 33, 0, 211, 243, 12, 93, ...>>)
      %EllipticCurve.Signature{r: 95867440227398247533351136059968563162267771464707645727187625451839377520639, s: 35965164910442916948460815891253401171705649249124379540577916592403246631835}
  """
  def fromDer!(der) do
    {rs, firstEmpty} = Der.removeSequence(der)

    if byte_size(firstEmpty) > 0 do
      raise "trailing junk after DER signature: " <> BinaryAscii.hexFromBinary(firstEmpty)
    end

    {r, rest} = Der.removeInteger(rs)
    {s, secondEmpty} = Der.removeInteger(rest)

    if byte_size(secondEmpty) > 0 do
      raise "trailing junk after DER numbers: " <> BinaryAscii.hexFromBinary(secondEmpty)
    end

    %Signature{r: r, s: s}
  end

  @doc """
  Converts a signature in decoded struct format into a base 64 string

  Parameters:
  - signature [%EllipticCurve.Signature]: decoded signature struct;

  Returns:
  - base64 [string]: signature in base 64 format

  ## Example:

      iex> EllipticCurve.Ecdsa.toBase64(%EllipticCurve.Signature{r: 123, s: 456})
      "YXNvZGlqYW9pZGphb2lkamFvaWRqc2Fpb3NkamE="
  """
  def toBase64(signature) do
    signature
    |> toDer()
    |> Base64.encode()
  end

  @doc """
  Converts a signature in decoded struct format into der format (raw binary)

  Parameters:
  - signature [%EllipticCurve.Signature]: decoded signature struct;

  Returns:
  - der [string]: signature in der format

  ## Example:

      iex> EllipticCurve.Ecdsa.toDer(%EllipticCurve.Signature{r: 95867440227398247533351136059968563162267771464707645727187625451839377520639, s: 35965164910442916948460815891253401171705649249124379540577916592403246631835})
      <<48, 69, 2, 33, 0, 211, 243, 12, 93, 107, 214, 149, 243, ...>>
  """
  def toDer(signature) do
    Der.encodeSequence([
      Der.encodeInteger(signature.r),
      Der.encodeInteger(signature.s)
    ])
  end
end
