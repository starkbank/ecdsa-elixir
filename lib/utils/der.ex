defmodule EllipticCurve.Utils.Der do
  @moduledoc false

  use Bitwise

  @hexAt "\x00"
  @hexB "\x02"
  @hexC "\x03"
  @hexD "\x04"
  @hexF "\x06"
  @hex0 "\x30"

  @hex31 0x1F
  @hex127 0x7F
  @hex129 0xA0
  @hex160 0x80
  @hex224 0xE0

  alias EllipticCurve.Utils.{BinaryAscii, Base64}

  def encodeSequence(encodedPieces) do
    Enum.sum(for piece <- encodedPieces, do: byte_size(piece))
    |> (fn totalLength -> <<@hex0>> <> encodeLength(totalLength) <> Enum.join(encodedPieces) end).()
  end

  def encodeInteger(x) when x >= 0 do
    bin =
      x
      |> Integer.to_string(16)
      |> complementIntegerString()
      |> BinaryAscii.binaryFromHex()

    if getFirstByte(bin) <= @hex127 do
      @hexB <> <<byte_size(bin)>> <> bin
    else
      @hexB <> <<byte_size(bin) + 1>> <> @hexAt <> bin
    end
  end

  defp complementIntegerString(x) when rem(byte_size(x), 2) == 1 do
    "0" <> x
  end

  defp complementIntegerString(x) do
    x
  end

  def encodeOid([first | [second | pieces]]) when first <= 2 and second <= 39 do
    (<<40 * first + second>> <> to_string(for piece <- pieces, do: encodeNumber(piece)))
    |> Enum.join()
    |> (fn body -> @hexF <> encodeLength(byte_size(body)) <> body end).()
  end

  def encodeBitString(t) do
    @hexC ++ encodeLength(byte_size(t)) ++ t
  end

  def encodeOctetString(t) do
    @hexD ++ encodeLength(byte_size(t)) ++ t
  end

  def encodeConstructed(tag, value) do
    [@hex129 + tag] ++ encodeLength(byte_size(value)) ++ value
  end

  def removeSequence(string) do
    trimmedString = checkSequenceError(string, @hex0)

    splitOnLength(trimmedString)
  end

  def removeInteger(string) do
    trimmedString = checkSequenceError(string, @hexB)

    {numberBytes, rest} = splitOnLength(trimmedString)

    if getFirstByte(numberBytes) >= @hex160 do
      throw("nBytes #{getFirstByte(numberBytes)} >= #{@hex160}")
    end

    {parsed, ""} =
      Integer.parse(
        BinaryAscii.hexFromBinary(numberBytes),
        16
      )

    {
      parsed,
      rest
    }
  end

  def removeObject(string) do
    trimmedString = checkSequenceError(string, @hexF)

    {body, rest} = splitOnLength(trimmedString)

    [n0 | numbers] = removeObjectRecursion(body)

    first = div(n0, 40)
    second = n0 - 40 * first

    {[first, second] ++ numbers, rest}
  end

  defp removeObjectRecursion(body) when byte_size(body) == 0 do
    []
  end

  defp removeObjectRecursion(body) do
    {n, lengthLength} = readNumber(body)

    numbers =
      binary_part(body, lengthLength, byte_size(body) - lengthLength)
      |> removeObjectRecursion()

    [n | numbers]
  end

  def removeBitString(string) do
    trimmedString = checkSequenceError(string, @hexC)

    splitOnLength(trimmedString)
  end

  def removeOctetString(string) do
    trimmedString = checkSequenceError(string, @hexD)

    splitOnLength(trimmedString)
  end

  def removeConstructed(<<s0>> <> trimmedString) do
    if (s0 &&& @hex224) != @hex129 do
      throw("wanted constructed tag (0xa0-0xbf), got #{Integer.to_string(s0, 16)}")
    end

    {body, rest} = splitOnLength(trimmedString)

    {
      s0 &&& @hex31,
      body,
      rest
    }
  end

  def fromPem(pem) do
    pem
    |> :binary.split(["\r", "\n", "\r\n"], [:global])
    |> filterPemLine()
    |> Enum.join()
    |> Base64.decode()
  end

  defp filterPemLine([line | rest]) do
    lines = filterPemLine(rest)
    cleanLine = line |> String.trim()

    if byte_size(cleanLine) == 0 or String.starts_with?(cleanLine, "-----") do
      lines
    else
      [line | lines]
    end
  end

  defp filterPemLine([]) do
    []
  end

  def toPem(der, name) do
    b64 =
      der
      |> Base64.encode()
      |> makeLines()

    (["-----BEGIN #{name}-----\n"] ++ b64 ++ ["-----END #{name}-----\n"])
    |> Enum.join()
  end

  defp makeLines(content) when byte_size(content) > 64 do
    [
      binary_part(content, 0, 64) <> "\n"
      | makeLines(binary_part(content, 64, byte_size(content) - 64))
    ]
  end

  defp makeLines(content) do
    [content <> "\n"]
  end

  def encodeLength(lengthValue) when lengthValue > 0 and lengthValue < @hex160 do
    <<lengthValue>>
  end

  def encodeLength(lengthValue) when lengthValue > 0 do
    lengthValue
    |> Integer.to_string(16)
    |> checkOddity()
    |> BinaryAscii.binaryFromHex()
    |> (fn s -> <<@hex160 ||| byte_size(s)>> <> s end).()
  end

  defp checkOddity(s) when rem(byte_size(s), 2) == 1 do
    "0" <> s
  end

  defp checkOddity(s) do
    s
  end

  def encodeNumber(n) do
    encodeNumberRecursive(n)
    |> checkListLength()
    |> to_string()
  end

  defp encodeNumberRecursive(n) when n > 0 do
    recursive = encodeNumberRecursive(n >>> 7)

    if length(recursive) == 0 do
      [((n &&& @hex127) ||| @hex160) &&& @hex127]
    else
      recursive ++ [(n &&& @hex127) ||| @hex160]
    end
  end

  defp encodeNumberRecursive(_n) do
    []
  end

  defp checkListLength([]) do
    [0]
  end

  defp checkListLength(b128Digits) do
    b128Digits
  end

  defp readNumber(string, number \\ 0, lengthLength \\ 0) do
    if lengthLength > byte_size(string) do
      throw("ran out of length bytes")
    end

    if lengthLength > 0 and
         (getFirstByte(binary_part(string, lengthLength - 1, 1)) &&& @hex160) == 0 do
      {number, lengthLength}
    else
      readNumber(
        string,
        (number <<< 7) + (getFirstByte(binary_part(string, lengthLength, 1)) &&& @hex127),
        lengthLength + 1
      )
    end
  end

  defp splitOnLength(string) do
    {bodyLength, lengthLength} = readLength(string)

    {
      binary_part(string, lengthLength, bodyLength),
      binary_part(
        string,
        bodyLength + lengthLength,
        byte_size(string) - lengthLength - bodyLength
      )
    }
  end

  defp readLength(string) do
    num = getFirstByte(string)

    if (num &&& @hex160) == 0 do
      {num &&& @hex127, 1}
    else
      lengthLength = num &&& @hex127

      if lengthLength > byte_size(string) - 1 do
        throw("ran out of length bytes")
      end

      {parsed, ""} =
        Integer.parse(
          BinaryAscii.hexFromBinary(binary_part(string, 1, lengthLength)),
          16
        )

      {
        parsed,
        1 + lengthLength
      }
    end
  end

  defp checkSequenceError(<<first>> <> rest, start) do
    if <<first>> != start do
      throw("wanted sequence #{Base.encode16(start)}, got #{Base.encode16(<<first>>)}")
    end

    rest
  end

  defp getFirstByte(<<first>> <> _rest) do
    first
  end
end
