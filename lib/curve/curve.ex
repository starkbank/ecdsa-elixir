defmodule EllipticCurve.Curve do
  @moduledoc false

  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Math

  @doc """
  Specific elliptic curve data.

  Parameters:
    - `:A` [number]: angular coefficient of x in the curve equation
    - `:B` [number]: linear coefficient of x in the curve equation
    - `:P` [number]: curve modulo
    - `:N` [number]: curve order
    - `:G` [EllipticCurve.Point]: generator point
    - `:name` [string]: curve name
    - `:nistName` [string]: NIST name (optional)
    - `:oid` [list of numbers]: ASN.1 Object Identifier
  """
  defstruct [:A, :B, :P, :N, :G, :name, :oid, :nistName]

  @doc """
  Verifies if the point `p` is on the curve using the elliptic curve equation:
  y^2 = x^3 + A*x + B (mod P)
  """
  def contains?(curve, p) do
    cond do
      p.x < 0 or p.x > curve."P" - 1 -> false
      p.y < 0 or p.y > curve."P" - 1 -> false
      IntegerUtils.modulo(
        IntegerUtils.ipow(p.y, 2) - (IntegerUtils.ipow(p.x, 3) + curve."A" * p.x + curve."B"),
        curve."P"
      ) != 0 -> false
      true -> true
    end
  end

  @doc """
  Gets the curve length (byte length of N).
  """
  def getLength(curve) do
    div(1 + String.length(Integer.to_string(curve."N", 16)), 2)
  end

  @doc """
  Compute the y coordinate for a given x on the curve.
  """
  def y(curve, x, isEven) do
    ySquared = IntegerUtils.modulo(
      IntegerUtils.mod_pow(x, 3, curve."P") + curve."A" * x + curve."B",
      curve."P"
    )

    y_val = Math.modularSquareRoot(ySquared, curve."P")

    if isEven != (rem(y_val, 2) == 0) do
      curve."P" - y_val
    else
      y_val
    end
  end
end
