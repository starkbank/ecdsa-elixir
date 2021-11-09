defmodule EllipticCurve.Curve do
  @moduledoc false

  alias EllipticCurve.Utils.Integer, as: IntegerUtils

  @doc """
  Verifies if the point `p` is on the curve using the elliptic curve equation:
  y^2 = x^3 + A*x + B (mod P)
  """
  def contains?(curveData, p) do
    cond do
      p.x < 0 || p.x > curveData."P" - 1 -> false
      p.y < 0 || p.y > curveData."P" - 1 -> false
      IntegerUtils.modulo(
        IntegerUtils.ipow(p.y, 2) -
          (IntegerUtils.ipow(p.x, 3) + curveData."A" * p.x + curveData."B"),
        curveData."P"
      ) != 0 -> false
      true -> true
    end
  end

  @doc """
  Gets the curve length
  """
  def getLength(curveData) do
    div(1 + String.length(Integer.to_string(curveData."N", 16)), 2)
  end
end
