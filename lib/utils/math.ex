defmodule EllipticCurve.Utils.Math do
  @moduledoc false

  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Utils.{Point}

  @doc """
  Fast way to multily point and scalar in elliptic curves

  :param p: First Point to mutiply
  :param n: Scalar to mutiply
  :param N: Order of the elliptic curve
  :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
  :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
  :return: Point that represents the sum of First and Second Point
  """
  def multiply(p, n, N, A, P) do
    toJacobian(p)
    |> jacobianMultiply(n, N, A, P)
    |> fromJacobian(P)
  end

  @doc """
  Fast way to add two points in elliptic curves

  :param p: First Point you want to add
  :param q: Second Point you want to add
  :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
  :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
  :return: Point that represents the sum of First and Second Point
  """
  def add(p, q, A, P) do
    jacobianAdd(toJacobian(p), toJacobian(q), A, P)
    |> fromJacobian(P)
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
    {lm, hm} = {1, 0}
    {low, high} = {IntegerUtils.modulo(x, n), n}

    invOperator(lm, hm, low, high)
    |> IntegerUtils.modulo(n)
  end

  defp invOperator(lm, hm, low, high) when low > 1 do
    r = rem(high, low)

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
  # :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
  # :return: Point in default coordinates
  defp toJacobian(p) do
    %Point{x: p.x, y: p.y, z: 1}
  end

  defp fromJacobian(p, P) do
    z = inv(p.z, P)

    %Point{
      x:
        IntegerUtils.modulo(
          IntegerUtils.ipow(p.x * z, 2),
          P
        ),
      y:
        IntegerUtils.modulo(
          IntegerUtils.ipow(p.y * z, 3),
          P
        ),
      z: 1
    }
  end

  # Doubles a point in elliptic curves
  # :param p: Point you want to double
  # :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
  # :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
  # :return: Point that represents the sum of First and Second Point
  defp jacobianDouble(p, A, P) do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 0}
    else
      ysq =
        IntegerUtils.ipow(p.y, 2)
        |> IntegerUtils.modulo(P)

      s =
        (4 * p.x * ysq)
        |> IntegerUtils.modulo(P)

      m =
        (3 * IntegerUtils.ipow(p.x, 2) + A * IntegerUtils.ipow(p.z, 4))
        |> IntegerUtils.modulo(P)

      nx =
        (IntegerUtils.ipow(m, 2) - 2 * s)
        |> IntegerUtils.modulo(P)

      ny =
        (m * (s - nx) - 8 * IntegerUtils.ipow(ysq, 2))
        |> IntegerUtils.modulo(P)

      nz =
        (2 * p.y * p.z)
        |> IntegerUtils.modulo(P)

      %Point{x: nx, y: ny, z: nz}
    end
  end

  # Adds two points in the elliptic curve
  # :param p: First Point you want to add
  # :param q: Second Point you want to add
  # :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
  # :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
  # :return: Point that represents the sum of First and Second Point
  defp jacobianAdd(p, q, A, P) do
    if p.y == 0 do
      q
    else
      if q.y == 0 do
        p
      else
        u1 =
          (p.x * IntegerUtils.ipow(q.z, 2))
          |> IntegerUtils.modulo(P)

        u2 =
          (q.x * IntegerUtils.ipow(p.z, 2))
          |> IntegerUtils.modulo(P)

        s1 =
          (p.y * IntegerUtils.ipow(q.z, 3))
          |> IntegerUtils.modulo(P)

        s2 =
          (q.y * IntegerUtils.ipow(p.z, 3))
          |> IntegerUtils.modulo(P)

        if u1 == u2 do
          if s1 != s2 do
            %Point{x: 0, y: 0, z: 1}
          else
            jacobianDouble(p, A, P)
          end
        else
          h = u2 - u1

          r = s2 - s1

          h2 =
            (h * h)
            |> IntegerUtils.modulo(P)

          h3 =
            (h * h2)
            |> IntegerUtils.modulo(P)

          u1h2 =
            (u1 * h2)
            |> IntegerUtils.modulo(P)

          nx =
            (IntegerUtils.ipow(r, 2) - h3 - 2 * u1h2)
            |> IntegerUtils.modulo(P)

          ny =
            (r * (u1h2 - nx) - s1 * h3)
            |> IntegerUtils.modulo(P)

          nz =
            (h * p.z * q.z)
            |> IntegerUtils.modulo(P)

          %Point{x: nx, y: ny, z: nz}
        end
      end
    end
  end

  # Multily point and scalar in elliptic curves
  # :param p: First Point to mutiply
  # :param n: Scalar to mutiply
  # :param N: Order of the elliptic curve
  # :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
  # :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
  # :return: Point that represents the sum of First and Second Point
  defp jacobianMultiply(p, n, N, A, P) when n < 0 or n >= N do
    if p.y == 0 or n == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      if n == 1 do
        p
      else
        jacobianMultiply(
          p,
          IntegerUtils.modulo(n, N),
          N,
          A,
          P
        )
      end
    end
  end

  defp jacobianMultiply(p, n, N, A, P) when n < 0 or n >= N do
    jacobianMultiply(p, IntegerUtils.modulo(n, N), N, A, P)
  end

  defp jacobianMultiply(p, n, N, A, P) when rem(n, 2) == 0 do
    jacobianMultiply(p, div(n, 2), N, A, P)
    |> jacobianDouble(A, P)
  end

  defp jacobianMultiply(p, n, N, A, P) do
    # rem(n, 2) == 1
    jacobianMultiply(p, div(n, 2), N, A, P)
    |> jacobianDouble(A, P)
    |> jacobianAdd(p, A, P)
  end
end
