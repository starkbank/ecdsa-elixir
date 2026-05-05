defmodule EllipticCurve.Utils.Integer do
  @moduledoc false

  import Bitwise

  def modulo(x, n) do
    rem(x, n)
    |> correctNegativeModulo(n)
  end

  defp correctNegativeModulo(r, n) when r < 0 do
    r + n
  end

  defp correctNegativeModulo(r, _n) do
    r
  end

  def ipow(base, p, acc \\ 1)

  def ipow(base, p, acc) when p > 0 do
    ipow(base, p - 1, base * acc)
  end

  def ipow(_base, _p, acc) do
    acc
  end

  @doc """
  Modular exponentiation: base^exp mod m
  Uses Erlang's built-in :crypto.mod_pow for efficiency.
  """
  def mod_pow(_base, _exp, 1), do: 0

  def mod_pow(base, exp, m) do
    base_val = modulo(base, m)
    base_bytes = if base_val == 0, do: <<0>>, else: :binary.encode_unsigned(base_val)
    exp_bytes = if exp == 0, do: <<0>>, else: :binary.encode_unsigned(exp)
    m_bytes = :binary.encode_unsigned(m)
    result = :crypto.mod_pow(base_bytes, exp_bytes, m_bytes)
    :binary.decode_unsigned(result)
  end

  @doc """
  Return integer bit length (number of bits needed to represent the integer).
  """
  def bit_length(0), do: 0

  def bit_length(n) when n > 0 do
    do_bit_length(n, 0)
  end

  defp do_bit_length(0, acc), do: acc

  defp do_bit_length(n, acc) do
    do_bit_length(n >>> 1, acc + 1)
  end

  def between(minimum, maximum) when minimum < maximum do
    range = maximum - minimum + 1
    {bytesNeeded, mask} = calculateParameters(range)

    randomNumber =
      :crypto.strong_rand_bytes(bytesNeeded)
      |> :binary.bin_to_list()
      |> bytesToNumber() &&& mask

    if randomNumber < range do
      minimum + randomNumber
    else
      between(minimum, maximum)
    end
  end

  @doc """
  Generate nonce values per hedged RFC 6979: deterministic k derivation
  with fresh random entropy mixed into K-init (RFC 6979 §3.6). Same message
  and key yield different signatures, while preserving RFC 6979's protection
  against RNG failures.
  Returns the HMAC-DRBG state {k, v} and parameters needed to generate candidates.
  """
  def rfc6979_init(hashBytes, secret, curve, hashfunc) do
    orderBitLen = EllipticCurve.Curve.nBitLength(curve)
    orderByteLen = div(orderBitLen + 7, 8)

    secretHex = Integer.to_string(secret, 16) |> String.pad_leading(orderByteLen * 2, "0")
    secretBytes = Base.decode16!(secretHex, case: :mixed)

    hashReduced = modulo(numberFromByteString(hashBytes, orderBitLen), curve."N")
    hashHex = Integer.to_string(hashReduced, 16) |> String.pad_leading(orderByteLen * 2, "0")
    hashOctets = Base.decode16!(hashHex, case: :mixed)

    extraEntropy = :crypto.strong_rand_bytes(orderByteLen)

    hLen = byte_size(:crypto.hash(hashfunc, <<>>))
    v = :binary.copy(<<1>>, hLen)
    k = :binary.copy(<<0>>, hLen)

    k = :crypto.mac(:hmac, hashfunc, k, v <> <<0>> <> secretBytes <> hashOctets <> extraEntropy)
    v = :crypto.mac(:hmac, hashfunc, k, v)
    k = :crypto.mac(:hmac, hashfunc, k, v <> <<1>> <> secretBytes <> hashOctets <> extraEntropy)
    v = :crypto.mac(:hmac, hashfunc, k, v)

    {k, v, orderBitLen, curve."N", hashfunc}
  end

  @doc """
  Get next valid k from RFC 6979 HMAC-DRBG state.
  Returns {k_value, new_state}.
  """
  def rfc6979_next({k, v, orderBitLen, n, hashfunc}) do
    {t, v} = collect_bits(k, v, orderBitLen, hashfunc, <<>>)
    candidate = numberFromByteString(t, orderBitLen)

    if candidate >= 1 and candidate <= n - 1 do
      {candidate, {k, v, orderBitLen, n, hashfunc}}
    else
      k = :crypto.mac(:hmac, hashfunc, k, v <> <<0>>)
      v = :crypto.mac(:hmac, hashfunc, k, v)
      rfc6979_next({k, v, orderBitLen, n, hashfunc})
    end
  end

  defp collect_bits(k, v, orderBitLen, hashfunc, t) when bit_size(t) < orderBitLen do
    v = :crypto.mac(:hmac, hashfunc, k, v)
    collect_bits(k, v, orderBitLen, hashfunc, t <> v)
  end

  defp collect_bits(_k, v, _orderBitLen, _hashfunc, t) do
    {t, v}
  end

  @doc """
  Convert a byte string to an integer, with optional right-shift for hash truncation.
  """
  def numberFromByteString(byteString, bitLength \\ nil) do
    number = :binary.decode_unsigned(byteString)

    if bitLength != nil do
      hashBitLen = byte_size(byteString) * 8

      if hashBitLen > bitLength do
        number >>> (hashBitLen - bitLength)
      else
        number
      end
    else
      number
    end
  end

  defp bytesToNumber(randomBytes, randomNumber \\ 0, i \\ 0)

  defp bytesToNumber([randomByte | otherRandomBytes], randomNumber, i) do
    bytesToNumber(
      otherRandomBytes,
      randomNumber ||| randomByte <<< (8 * i),
      i + 1
    )
  end

  defp bytesToNumber([], randomNumber, _i) do
    randomNumber
  end

  defp calculateParameters(range) do
    calculateParameters(range, 1, 0)
  end

  defp calculateParameters(range, mask, bitsNeeded) when range > 0 do
    calculateParameters(
      range >>> 1,
      mask <<< 1 ||| 1,
      bitsNeeded + 1
    )
  end

  defp calculateParameters(_range, mask, bitsNeeded) do
    {div(bitsNeeded, 8) + 1, mask}
  end
end
