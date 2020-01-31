defmodule EllipticCurve.Curve do
  @moduledoc false

  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Curve.KnownCurves, as: KnownCurves

  @doc """
  Verifies if the point `p` is on the curve using the elliptic curve equation:
  y^2 = x^3 + A*x + B (mod P)
  """
  def contains?(curve, p) do
    IntegerUtils.modulo(
      IntegerUtils.ipow(p.y, 2) - (IntegerUtils.ipow(p.x, 3) + curve.A * p.x + curve.B),
      curve.P
    ) == 0
  end

  @doc """
  Gets the curve length
  """
  def getLength(curve) do
    div(1 + String.length(Integer.to_string(curve.N, 16)), 2)
  end

  def getCurveByOid(oid) do
    case do
      KnownCurves.secp256k1().oid -> KnownCurves.secp256k1()
      KnownCurves.prime256v1().oid -> KnownCurves.prime256v1()
    end
  end

  def getCurveByName(name) do
    case do
      KnownCurves.secp256k1().name -> KnownCurves.secp256k1()
      KnownCurves.prime256v1().name -> KnownCurves.prime256v1()
    end
  end
end
