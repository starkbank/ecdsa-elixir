defmodule EllipticCurve.Math do
  @moduledoc false

  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Point

  use Bitwise

  @doc """
  Tonelli-Shanks algorithm for modular square root. Works for all odd primes.
  """
  def modularSquareRoot(value, _prime) when value == 0, do: 0

  def modularSquareRoot(value, prime) when prime == 2, do: IntegerUtils.modulo(value, 2)

  def modularSquareRoot(value, prime) do
    # Factor out powers of 2: prime - 1 = Q * 2^S
    {q, s} = factor_twos(prime - 1, 0)

    if s == 1 do
      # prime = 3 (mod 4) - fast path
      IntegerUtils.mod_pow(value, div(prime + 1, 4), prime)
    else
      # Find a quadratic non-residue z
      z = find_non_residue(2, prime)

      m = s
      c = IntegerUtils.mod_pow(z, q, prime)
      t = IntegerUtils.mod_pow(value, q, prime)
      r = IntegerUtils.mod_pow(value, div(q + 1, 2), prime)

      tonelli_loop(m, c, t, r, prime)
    end
  end

  defp factor_twos(q, s) when rem(q, 2) == 0, do: factor_twos(div(q, 2), s + 1)
  defp factor_twos(q, s), do: {q, s}

  defp find_non_residue(z, prime) do
    if IntegerUtils.mod_pow(z, div(prime - 1, 2), prime) == prime - 1 do
      z
    else
      find_non_residue(z + 1, prime)
    end
  end

  defp tonelli_loop(m, c, t, r, prime) do
    if t == 1 do
      r
    else
      # Find the least i such that t^(2^i) = 1 (mod prime)
      i = find_least_i(IntegerUtils.modulo(t * t, prime), 1, prime)

      b = IntegerUtils.mod_pow(c, 1 <<< (m - i - 1), prime)
      new_m = i
      new_c = IntegerUtils.modulo(b * b, prime)
      new_t = IntegerUtils.modulo(t * new_c, prime)
      new_r = IntegerUtils.modulo(r * b, prime)

      tonelli_loop(new_m, new_c, new_t, new_r, prime)
    end
  end

  defp find_least_i(temp, i, prime) do
    if temp == 1 do
      i
    else
      find_least_i(IntegerUtils.modulo(temp * temp, prime), i + 1, prime)
    end
  end

  @doc """
  Fast way to multiply point and scalar in elliptic curves

  - `p` [Point]: First Point to multiply
  - `n` [integer]: Scalar to multiply
  - `cN` [integer]: Order of the elliptic curve
  - `cA` [integer]: Coefficient of the first-order term
  - `cP` [integer]: Prime number in the module
  """
  def multiply(p, n, cN, cA, cP) do
    p
    |> toJacobian()
    |> jacobianMultiply(n, cN, cA, cP)
    |> fromJacobian(cP)
  end

  @doc """
  Fast way to add two points in elliptic curves
  """
  def add(p, q, cA, cP) do
    jacobianAdd(toJacobian(p), toJacobian(q), cA, cP)
    |> fromJacobian(cP)
  end

  @doc """
  Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
  Not constant-time -- use only with public scalars (e.g. verification).
  """
  def multiplyAndAdd(p1, n1, p2, n2, cN, cA, cP) do
    shamirMultiply(
      toJacobian(p1), n1,
      toJacobian(p2), n2,
      cN, cA, cP
    )
    |> fromJacobian(cP)
  end

  @doc """
  Modular inverse using Fermat's little theorem: x^(n-2) mod n.
  Requires n to be prime (true for all ECDSA curve parameters).
  """
  def inv(0, _n), do: 0

  def inv(x, n) do
    IntegerUtils.mod_pow(x, n - 2, n)
  end

  # Convert point to Jacobian coordinates
  defp toJacobian(p) do
    %Point{x: p.x, y: p.y, z: 1}
  end

  # Convert point back from Jacobian coordinates
  # Guard: handle point at infinity
  defp fromJacobian(%Point{y: 0}, _cP) do
    %Point{x: 0, y: 0, z: 0}
  end

  defp fromJacobian(p, cP) do
    z = inv(p.z, cP)
    z2 = IntegerUtils.modulo(z * z, cP)
    z3 = IntegerUtils.modulo(z2 * z, cP)

    %Point{
      x: IntegerUtils.modulo(p.x * z2, cP),
      y: IntegerUtils.modulo(p.y * z3, cP)
    }
  end

  # Double a point in elliptic curves (Jacobian)
  defp jacobianDouble(%Point{y: 0}, _cA, _cP) do
    %Point{x: 0, y: 0, z: 0}
  end

  defp jacobianDouble(p, cA, cP) do
    py = p.y
    px = p.x
    pz = p.z

    ysq = IntegerUtils.modulo(py * py, cP)
    s = IntegerUtils.modulo(4 * px * ysq, cP)
    pz2 = IntegerUtils.modulo(pz * pz, cP)
    m = IntegerUtils.modulo(3 * px * px + cA * pz2 * pz2, cP)
    nx = IntegerUtils.modulo(m * m - 2 * s, cP)
    ny = IntegerUtils.modulo(m * (s - nx) - 8 * ysq * ysq, cP)
    nz = IntegerUtils.modulo(2 * py * pz, cP)

    %Point{x: nx, y: ny, z: nz}
  end

  # Add two points in elliptic curves (Jacobian)
  defp jacobianAdd(%Point{y: 0}, q, _cA, _cP), do: q
  defp jacobianAdd(p, %Point{y: 0}, _cA, _cP), do: p

  defp jacobianAdd(p, q, cA, cP) do
    px = p.x
    py = p.y
    pz = p.z
    qx = q.x
    qy = q.y
    qz = q.z

    qz2 = IntegerUtils.modulo(qz * qz, cP)
    pz2 = IntegerUtils.modulo(pz * pz, cP)
    u1 = IntegerUtils.modulo(px * qz2, cP)
    u2 = IntegerUtils.modulo(qx * pz2, cP)
    s1 = IntegerUtils.modulo(py * qz2 * qz, cP)
    s2 = IntegerUtils.modulo(qy * pz2 * pz, cP)

    if u1 == u2 do
      if s1 != s2 do
        %Point{x: 0, y: 0, z: 1}
      else
        jacobianDouble(p, cA, cP)
      end
    else
      h = u2 - u1
      r = s2 - s1
      h2 = IntegerUtils.modulo(h * h, cP)
      h3 = IntegerUtils.modulo(h * h2, cP)
      u1h2 = IntegerUtils.modulo(u1 * h2, cP)
      nx = IntegerUtils.modulo(r * r - h3 - 2 * u1h2, cP)
      ny = IntegerUtils.modulo(r * (u1h2 - nx) - s1 * h3, cP)
      nz = IntegerUtils.modulo(h * pz * qz, cP)

      %Point{x: nx, y: ny, z: nz}
    end
  end

  # Montgomery ladder: constant-time scalar multiplication
  defp jacobianMultiply(%Point{y: 0}, _n, _cN, _cA, _cP) do
    %Point{x: 0, y: 0, z: 1}
  end

  defp jacobianMultiply(_p, 0, _cN, _cA, _cP) do
    %Point{x: 0, y: 0, z: 1}
  end

  defp jacobianMultiply(p, n, cN, _cA, _cP) when n < 0 or n >= cN do
    n = IntegerUtils.modulo(n, cN)

    if n == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      jacobianMultiply(p, n, cN, _cA, _cP)
    end
  end

  defp jacobianMultiply(p, n, _cN, cA, cP) do
    bitLen = IntegerUtils.bit_length(n)

    r0 = %Point{x: 0, y: 0, z: 1}
    r1 = %Point{x: p.x, y: p.y, z: p.z}

    montgomery_loop(r0, r1, bitLen - 1, n, cA, cP)
  end

  defp montgomery_loop(r0, _r1, i, _n, _cA, _cP) when i < 0, do: r0

  defp montgomery_loop(r0, r1, i, n, cA, cP) do
    if (n >>> i &&& 1) == 0 do
      new_r1 = jacobianAdd(r0, r1, cA, cP)
      new_r0 = jacobianDouble(r0, cA, cP)
      montgomery_loop(new_r0, new_r1, i - 1, n, cA, cP)
    else
      new_r0 = jacobianAdd(r0, r1, cA, cP)
      new_r1 = jacobianDouble(r1, cA, cP)
      montgomery_loop(new_r0, new_r1, i - 1, n, cA, cP)
    end
  end

  # Shamir's trick: simultaneous double-and-add for n1*p1 + n2*p2
  defp shamirMultiply(jp1, n1, jp2, n2, cN, cA, cP) do
    n1 = if n1 < 0 or n1 >= cN, do: IntegerUtils.modulo(n1, cN), else: n1
    n2 = if n2 < 0 or n2 >= cN, do: IntegerUtils.modulo(n2, cN), else: n2

    jp1p2 = jacobianAdd(jp1, jp2, cA, cP)

    l = max(IntegerUtils.bit_length(n1), IntegerUtils.bit_length(n2))
    r = %Point{x: 0, y: 0, z: 1}

    shamir_loop(r, l - 1, n1, n2, jp1, jp2, jp1p2, cA, cP)
  end

  defp shamir_loop(r, i, _n1, _n2, _jp1, _jp2, _jp1p2, _cA, _cP) when i < 0, do: r

  defp shamir_loop(r, i, n1, n2, jp1, jp2, jp1p2, cA, cP) do
    r = jacobianDouble(r, cA, cP)
    b1 = n1 >>> i &&& 1
    b2 = n2 >>> i &&& 1

    r =
      cond do
        b1 == 1 and b2 == 1 -> jacobianAdd(r, jp1p2, cA, cP)
        b1 == 1 -> jacobianAdd(r, jp1, cA, cP)
        b2 == 1 -> jacobianAdd(r, jp2, cA, cP)
        true -> r
      end

    shamir_loop(r, i - 1, n1, n2, jp1, jp2, jp1p2, cA, cP)
  end
end
