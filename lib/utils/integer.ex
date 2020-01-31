defmodule EllipticCurve.Utils.Integer do
  @moduledoc false

  use Bitwise

  # 2 ^ 256
  @defaultRandomMaximum 115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_936

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

  def between(
        minimum \\ 0,
        maximum \\ @defaultRandomMaximum
      )
      when minimum < maximum do
    range = maximum - minimum + 1
    {bytesNeeded, mask} = calculateParameters(range)

    #  We apply the mask to reduce the amount of attempts we might need
    #     to make to get a number that is in range. This is somewhat like
    #     the commonly used 'modulo trick', but without the bias:
    #    
    #       "Let's say you invoke secure_rand(0, 60). When the other code
    #        generates a random integer, you might get 243. If you take
    #        (243 & 63)-- noting that the mask is 63-- you get 51. Since
    #        51 is less than 60, we can return this without bias. If we
    #        got 255, then 255 & 63 is 63. 63 > 60, so we try again.
    #    
    #        The purpose of the mask is to reduce the number of random
    #        numbers discarded for the sake of ensuring an unbiased
    #        distribution. In the example above, 243 would discard, but
    #        (243 & 63) is in the range of 0 and 60."
    #    
    #       (Source: Scott Arciszewski)

    randomNumber =
      :crypto.strong_rand_bytes(bytesNeeded)
      # |> IO.inspect()
      |> :binary.bin_to_list()
      # |> IO.inspect()
      |> bytesToNumber &&& mask

    if randomNumber < range do
      minimum + randomNumber
    else
      # Outside of the acceptable range, throw it away and try again.
      # We don't try any modulo tricks, as this would introduce bias.
      between(minimum, maximum)
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
