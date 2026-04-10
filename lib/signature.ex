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
  - `:r` [integer]: first signature number;
  - `:s` [integer]: second signature number;
  - `:recoveryId` [integer]: recovery id for public key recovery (optional);
  """
  defstruct [:r, :s, :recoveryId]

  @doc """
  Converts a base 64 signature into the decoded struct format
  """
  def fromBase64(base64String, opts \\ []) do
    {:ok, fromBase64!(base64String, opts)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  def fromBase64!(base64String, opts \\ []) do
    recoveryByte = Keyword.get(opts, :recoveryByte, false)

    base64String
    |> Base64.decode()
    |> fromDer!(recoveryByte: recoveryByte)
  end

  @doc """
  Converts a der signature (raw binary) into the decoded struct format
  """
  def fromDer(der, opts \\ []) do
    {:ok, fromDer!(der, opts)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  def fromDer!(der, opts \\ []) do
    recoveryByte = Keyword.get(opts, :recoveryByte, false)

    {recoveryId, der} =
      if recoveryByte do
        <<firstByte, rest::binary>> = der
        {firstByte - 27, rest}
      else
        {nil, der}
      end

    {rs, firstEmpty} = Der.removeSequence(der)

    if byte_size(firstEmpty) > 0 do
      raise "trailing junk after DER signature: " <> BinaryAscii.hexFromBinary(firstEmpty)
    end

    {r, rest} = Der.removeInteger(rs)
    {s, secondEmpty} = Der.removeInteger(rest)

    if byte_size(secondEmpty) > 0 do
      raise "trailing junk after DER numbers: " <> BinaryAscii.hexFromBinary(secondEmpty)
    end

    %Signature{r: r, s: s, recoveryId: recoveryId}
  end

  @doc """
  Converts a signature in decoded struct format into a base 64 string
  """
  def toBase64(signature, opts \\ []) do
    signature
    |> toDer(opts)
    |> Base64.encode()
  end

  @doc """
  Converts a signature in decoded struct format into der format (raw binary)
  """
  def toDer(signature, opts \\ []) do
    withRecoveryId = Keyword.get(opts, :withRecoveryId, false)

    encodedSequence = Der.encodeSequence([
      Der.encodeInteger(signature.r),
      Der.encodeInteger(signature.s)
    ])

    if withRecoveryId do
      <<27 + signature.recoveryId>> <> encodedSequence
    else
      encodedSequence
    end
  end
end
