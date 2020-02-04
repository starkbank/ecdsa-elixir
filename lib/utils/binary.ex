defmodule EllipticCurve.Utils.BinaryAscii do
  @moduledoc false

  @doc """
  Return the hexadecimal representation of the binary data. Every byte of data is converted into the
  corresponding 2-digit hex representation. The resulting string is therefore twice as long as the length of data.

  :param data: binary
  :return: hexadecimal string
  """
  def hexFromBinary(data) do
    Base.encode16(data)
  end

  @doc """
  Return the binary data represented by the hexadecimal string hexstr. This function is the inverse of b2a_hex().
  hexstr must contain an even number of hexadecimal digits (which can be upper or lower case), otherwise a TypeError is raised.

  :param data: hexadecimal string
  :return: binary
  """
  def binaryFromHex(data) do
    Base.decode16!(data)
  end

  @doc """
  Get a number representation of a string

  :param String to be converted in a number
  :return: Number in hex from string
  """
  def numberFromString(string) do
    hexFromBinary(string)
    |> Integer.parse(16)
    |> (fn {parsedInt, ""} -> parsedInt end).()
  end

  @doc """
  Get a string representation of a number

  :param number to be converted in a string
  :param length max number of character for the string
  :return: hexadecimal string
  """
  def stringFromNumber(number, stringLength) do
    number
    |> Integer.to_string(16)
    |> fillNumberString(stringLength)
    |> binaryFromHex()
  end

  defp fillNumberString(string, stringLength) do
    String.duplicate("0", 2 * stringLength - byte_size(string)) <> string
  end
end
