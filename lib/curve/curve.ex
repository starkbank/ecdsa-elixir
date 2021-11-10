defmodule EllipticCurve.Curve do
  @moduledoc false

  alias EllipticCurve.Utils.Integer, as: IntegerUtils

  @doc """
  Specific elliptic curve data.

  Attributes (return-only):
    - `:A` [number]: angular coefficient of x in the curve equation. ex: 123
    - `:B` [number]: linear coefficient of x in the curve equation. ex: 123
    - `:P` [number]: curve modulo. ex: 12345
    - `:N` [number]: curve order. ex: 12345
    - `:G` [EllipticCurve.Point]: EC Point corresponding to the public key. ex: %Point{x: 123, y: 456}
    - `:name` [string]: curve name. ex: "secp256k1"
    - `:oid` [list of numbers]: ASN.1 Object Identifier. ex: "checking"
  """
  defstruct [:A, :B, :P, :N, :G, :name, :oid]

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
