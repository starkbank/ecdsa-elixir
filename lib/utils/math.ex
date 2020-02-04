defmodule EllipticCurve.Utils.Math do
  @moduledoc false

  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Utils.{Point}

  @doc """
  Fast way to multily point and scalar in elliptic curves

  :param p: First Point to mutiply
  :param n: Scalar to mutiply
  :param cN: Order of the elliptic curve
  :param cP: Prime number in the module of the equation Y^2 = X^3 + cA*X + B (mod p)
  :param cA: Coefficient of the first-order term of the equation Y^2 = X^3 + cA*X + B (mod p)
  :return: Point that represents the sum of First and Second Point
  """
  def multiply(p, n, cN, cA, cP) do
    p
    |> toJacobian()
    |> jacobianMultiply(n, cN, cA, cP)
    |> fromJacobian(cP)
  end

  @doc """
  Fast way to add two points in elliptic curves

  :param p: First Point you want to add
  :param q: Second Point you want to add
  :param cP: Prime number in the module of the equation Y^2 = X^3 + cA*X + B (mod p)
  :param cA: Coefficient of the first-order term of the equation Y^2 = X^3 + cA*X + B (mod p)
  :return: Point that represents the sum of First and Second Point
  """
  def add(p, q, cA, cP) do
    jacobianAdd(toJacobian(p), toJacobian(q), cA, cP)
    |> fromJacobian(cP)
  end

  @doc """
  Extended Euclidean Algorithm. It's the 'division' in elliptic curves

  :param x: Divisor
  :param n: Mod for division
  :return: Value representing the division
  """
  def inv(x, _n) when x == 0 do
    0
  end

  def inv(x, n) do
    invOperator(1, 0, IntegerUtils.modulo(x, n), n)
    |> IntegerUtils.modulo(n)
  end

  defp invOperator(lm, hm, low, high) when low > 1 do
    r = div(high, low)

    invOperator(
      hm - lm * r,
      lm,
      high - low * r,
      low
    )
  end

  defp invOperator(lm, _hm, _low, _high) do
    lm
  end

  # Converts point back from Jacobian coordinates
  # :param p: First Point you want to add
  # :param cP: Prime number in the module of the equation Y^2 = X^3 + cA*X + B (mod p)
  # :return: Point in default coordinates
  defp toJacobian(p) do
    %Point{x: p.x, y: p.y, z: 1}
  end

  defp fromJacobian(p, cP) do
    z = inv(p.z, cP)

    %Point{
      x:
        IntegerUtils.modulo(
          p.x * IntegerUtils.ipow(z, 2),
          cP
        ),
      y:
        IntegerUtils.modulo(
          p.y * IntegerUtils.ipow(z, 3),
          cP
        )
    }
  end

  # Doubles a point in elliptic curves
  # :param p: Point you want to double
  # :param cP: Prime number in the module of the equation Y^2 = X^3 + cA*X + B (mod p)
  # :param cA: Coefficient of the first-order term of the equation Y^2 = X^3 + cA*X + B (mod p)
  # :return: Point that represents the sum of First and Second Point
  defp jacobianDouble(p, cA, cP) do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 0}
    else
      ysq =
        IntegerUtils.ipow(p.y, 2)
        |> IntegerUtils.modulo(cP)

      s =
        (4 * p.x * ysq)
        |> IntegerUtils.modulo(cP)

      m =
        (3 * IntegerUtils.ipow(p.x, 2) + cA * IntegerUtils.ipow(p.z, 4))
        |> IntegerUtils.modulo(cP)

      nx =
        (IntegerUtils.ipow(m, 2) - 2 * s)
        |> IntegerUtils.modulo(cP)

      ny =
        (m * (s - nx) - 8 * IntegerUtils.ipow(ysq, 2))
        |> IntegerUtils.modulo(cP)

      nz =
        (2 * p.y * p.z)
        |> IntegerUtils.modulo(cP)

      %Point{x: nx, y: ny, z: nz}
    end
  end

  # Adds two points in the elliptic curve
  # :param p: First Point you want to add
  # :param q: Second Point you want to add
  # :param cP: Prime number in the module of the equation Y^2 = X^3 + cA*X + B (mod p)
  # :param cA: Coefficient of the first-order term of the equation Y^2 = X^3 + cA*X + B (mod p)
  # :return: Point that represents the sum of First and Second Point
  defp jacobianAdd(p, q, cA, cP) do
    if p.y == 0 do
      q
    else
      if q.y == 0 do
        p
      else
        u1 =
          (p.x * IntegerUtils.ipow(q.z, 2))
          |> IntegerUtils.modulo(cP)

        u2 =
          (q.x * IntegerUtils.ipow(p.z, 2))
          |> IntegerUtils.modulo(cP)

        s1 =
          (p.y * IntegerUtils.ipow(q.z, 3))
          |> IntegerUtils.modulo(cP)

        s2 =
          (q.y * IntegerUtils.ipow(p.z, 3))
          |> IntegerUtils.modulo(cP)

        if u1 == u2 do
          if s1 != s2 do
            %Point{x: 0, y: 0, z: 1}
          else
            jacobianDouble(p, cA, cP)
          end
        else
          h = u2 - u1

          r = s2 - s1

          h2 =
            (h * h)
            |> IntegerUtils.modulo(cP)

          h3 =
            (h * h2)
            |> IntegerUtils.modulo(cP)

          u1h2 =
            (u1 * h2)
            |> IntegerUtils.modulo(cP)

          nx =
            (IntegerUtils.ipow(r, 2) - h3 - 2 * u1h2)
            |> IntegerUtils.modulo(cP)

          ny =
            (r * (u1h2 - nx) - s1 * h3)
            |> IntegerUtils.modulo(cP)

          nz =
            (h * p.z * q.z)
            |> IntegerUtils.modulo(cP)

          %Point{x: nx, y: ny, z: nz}
        end
      end
    end
  end

  # Multily point and scalar in elliptic curves
  # :param p: First Point to mutiply
  # :param n: Scalar to mutiply
  # :param cN: Order of the elliptic curve
  # :param cP: Prime number in the module of the equation Y^2 = X^3 + cA*X + B (mod p)
  # :param cA: Coefficient of the first-order term of the equation Y^2 = X^3 + cA*X + B (mod p)
  # :return: Point that represents the sum of First and Second Point
  defp jacobianMultiply(_p, n, _cN, _cA, _cP) when n == 0 do
    %Point{x: 0, y: 0, z: 1}
  end

  defp jacobianMultiply(p, n, _cN, _cA, _cP) when n == 1 do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      p
    end
  end

  defp jacobianMultiply(p, n, cN, cA, cP) when n < 0 or n >= cN do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      jacobianMultiply(p, IntegerUtils.modulo(n, cN), cN, cA, cP)
    end
  end

  defp jacobianMultiply(p, n, cN, cA, cP) when rem(n, 2) == 0 do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      jacobianMultiply(p, div(n, 2), cN, cA, cP)
      |> jacobianDouble(cA, cP)
    end
  end

  defp jacobianMultiply(p, n, cN, cA, cP) do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      # rem(n, 2) == 1
      jacobianMultiply(p, div(n, 2), cN, cA, cP)
      |> jacobianDouble(cA, cP)
      |> jacobianAdd(p, cA, cP)
    end
  end
end
