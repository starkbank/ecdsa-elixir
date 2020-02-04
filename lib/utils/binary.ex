defmodule EllipticCurve.Utils.BinaryAscii do
  @moduledoc false

  def hexFromBinary(data) do
    Base.encode16(data)
  end

  def binaryFromHex(data) do
    Base.decode16!(data)
  end

  def numberFromString(string) do
    hexFromBinary(string)
    |> Integer.parse(16)
    |> (fn {parsedInt, ""} -> parsedInt end).()
  end

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
