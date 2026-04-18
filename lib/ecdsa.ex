defmodule EllipticCurve.Ecdsa do
  @moduledoc """
  Used to sign and verify signatures using the Elliptic Curve Digital Signature Algorithm (ECDSA)

  Functions:
  - `sign()`
  - `verify?()`
  """

  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.{Point, Signature, Math, Curve}

  use Bitwise

  @doc """
  Generates a message signature based on a private key.

  Uses RFC 6979 deterministic nonces, low-S normalization, and hash truncation.
  """
  def sign(message, privateKey, options \\ []) do
    %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})

    curveData = privateKey.curve
    byteMessage = :crypto.hash(hashfunc, message)
    numberMessage = IntegerUtils.numberFromByteString(byteMessage, Curve.nBitLength(curveData))

    state = IntegerUtils.rfc6979_init(byteMessage, privateKey.secret, curveData, hashfunc)

    {r, s, randSignPoint} = find_valid_rs(state, numberMessage, curveData, privateKey.secret)

    recoveryId = Bitwise.band(randSignPoint.y, 1)

    recoveryId =
      if randSignPoint.y > curveData."N" do
        recoveryId + 2
      else
        recoveryId
      end

    # Low-S normalization
    {s, recoveryId} =
      if s > div(curveData."N", 2) do
        {curveData."N" - s, Bitwise.bxor(recoveryId, 1)}
      else
        {s, recoveryId}
      end

    %Signature{r: r, s: s, recoveryId: recoveryId}
  end

  defp find_valid_rs(state, numberMessage, curveData, secret) do
    {randNum, newState} = IntegerUtils.rfc6979_next(state)

    randSignPoint = Math.multiplyGenerator(curveData, randNum)
    r = IntegerUtils.modulo(randSignPoint.x, curveData."N")
    s = IntegerUtils.modulo(
      (numberMessage + r * secret) * Math.inv(randNum, curveData."N"),
      curveData."N"
    )

    if r == 0 or s == 0 do
      find_valid_rs(newState, numberMessage, curveData, secret)
    else
      {r, s, randSignPoint}
    end
  end

  @doc """
  Verifies a message signature based on a public key.

  Includes public key on-curve validation and uses Shamir's trick for fast verification.
  """
  def verify?(message, signature, publicKey, options \\ []) do
    %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})

    curveData = publicKey.curve
    byteMessage = :crypto.hash(hashfunc, message)
    numberMessage = IntegerUtils.numberFromByteString(byteMessage, Curve.nBitLength(curveData))

    r = signature.r
    s = signature.s

    cond do
      r < 1 or r > curveData."N" - 1 -> false
      s < 1 or s > curveData."N" - 1 -> false
      not Curve.contains?(curveData, publicKey.point) -> false
      true ->
        inv = Math.inv(s, curveData."N")

        v = Math.multiplyAndAdd(
          curveData."G",
          IntegerUtils.modulo(numberMessage * inv, curveData."N"),
          publicKey.point,
          IntegerUtils.modulo(r * inv, curveData."N"),
          curveData."N",
          curveData."A",
          curveData."P"
        )

        if Point.isAtInfinity?(v) do
          false
        else
          IntegerUtils.modulo(v.x, curveData."N") == r
        end
    end
  end
end
