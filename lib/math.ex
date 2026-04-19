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
  Compute n1*p1 + n2*p2. If `curve` is given and exposes `glvParams`
  (e.g. secp256k1), uses the GLV endomorphism to split both scalars into
  ~128-bit halves and run a 4-scalar simultaneous multi-exponentiation.
  Otherwise falls back to Shamir's trick with JSF. Not constant-time --
  use only with public scalars (e.g. verification).
  """
  def multiplyAndAdd(p1, n1, p2, n2, cN, cA, cP) do
    shamirMultiply(
      toJacobian(p1), n1,
      toJacobian(p2), n2,
      cN, cA, cP
    )
    |> fromJacobian(cP)
  end

  def multiplyAndAdd(p1, n1, p2, n2, %EllipticCurve.Curve{glvParams: nil} = curve) do
    multiplyAndAdd(p1, n1, p2, n2, curve."N", curve."A", curve."P")
  end

  def multiplyAndAdd(p1, n1, p2, n2, %EllipticCurve.Curve{} = curve) do
    glvMultiplyAndAdd(p1, n1, p2, n2, curve)
    |> fromJacobian(curve."P")
  end

  @doc """
  Fast scalar multiplication n*G using a precomputed affine table of
  powers-of-two multiples of G and the width-2 NAF of n. Every non-zero
  NAF digit triggers one mixed add and zero doublings, trading the ~256
  doublings of a windowed method for ~86 adds on average -- a large net
  reduction in field multiplications for 256-bit scalars.
  """
  def multiplyGenerator(curve, n) do
    cN = curve."N"
    n = if n < 0 or n >= cN, do: IntegerUtils.modulo(n, cN), else: n

    if n == 0 do
      %Point{x: 0, y: 0, z: 0}
    else
      cA = curve."A"
      cP = curve."P"
      table = generatorPowersTable(curve)

      %Point{x: 0, y: 0, z: 1}
      |> naf_loop(n, 0, table, cA, cP)
      |> fromJacobian(cP)
    end
  end

  # Width-2 NAF: at each step, if k is odd, extract signed digit
  # 2 - (k & 3) in {-1, +1}, subtract from k, then shift right.
  defp naf_loop(r, 0, _i, _table, _cA, _cP), do: r

  defp naf_loop(r, k, i, table, cA, cP) do
    {r, k} =
      if (k &&& 1) == 1 do
        digit = 2 - (k &&& 3)
        g = elem(table, i)

        g_signed =
          if digit == 1 do
            g
          else
            %Point{x: g.x, y: cP - g.y, z: 1}
          end

        {jacobianAdd(r, g_signed, cA, cP), k - digit}
      else
        {r, k}
      end

    naf_loop(r, k >>> 1, i + 1, table, cA, cP)
  end

  defp generatorPowersTable(curve) do
    key = {__MODULE__, :generator_table, curve.name}

    case :persistent_term.get(key, :undefined) do
      :undefined ->
        table = buildGeneratorPowersTable(curve)
        :persistent_term.put(key, table)
        table

      table ->
        table
    end
  end

  # Build [G, 2G, 4G, ..., 2^nBitLength * G] in affine (z=1) form, so each
  # add in multiplyGenerator hits the mixed-add fast path.
  defp buildGeneratorPowersTable(curve) do
    cA = curve."A"
    cP = curve."P"
    nBitLen = EllipticCurve.Curve.nBitLength(curve)
    current = %Point{x: curve."G".x, y: curve."G".y, z: 1}

    # NAF of an nBitLength-bit scalar can be up to nBitLength+1 digits.
    entries =
      Enum.reduce(0..(nBitLen - 1), [current], fn _, [prev | _] = acc ->
        [double_to_affine(prev, cA, cP) | acc]
      end)

    entries
    |> Enum.reverse()
    |> List.to_tuple()
  end

  defp double_to_affine(p, cA, cP) do
    doubled = jacobianDouble(p, cA, cP)

    if doubled.y == 0 do
      doubled
    else
      zInv = inv(doubled.z, cP)
      zInv2 = IntegerUtils.modulo(zInv * zInv, cP)
      zInv3 = IntegerUtils.modulo(zInv2 * zInv, cP)

      %Point{
        x: IntegerUtils.modulo(doubled.x * zInv2, cP),
        y: IntegerUtils.modulo(doubled.y * zInv3, cP),
        z: 1
      }
    end
  end

  @doc """
  Modular inverse via extended Euclidean algorithm. Roughly 2-3x faster than
  Fermat's little theorem for 256-bit operands.
  """
  def inv(0, _n), do: 0

  def inv(x, n) do
    mod_inverse(x, n)
  end

  defp mod_inverse(x, n) do
    x = rem(x, n)
    x = if x < 0, do: x + n, else: x

    if x == 0 do
      raise ArgumentError, "0 has no modular inverse"
    end

    {g, s, _t} = extended_gcd(x, n)

    if g != 1 do
      raise ArgumentError, "no modular inverse"
    end

    rem(s + n, n)
  end

  defp extended_gcd(0, b), do: {b, 0, 1}

  defp extended_gcd(a, b) do
    {g, s, t} = extended_gcd(rem(b, a), a)
    {g, t - div(b, a) * s, s}
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

    m =
      cond do
        cA == 0 ->
          IntegerUtils.modulo(3 * px * px, cP)

        cA == cP - 3 ->
          IntegerUtils.modulo(3 * (px - pz2) * (px + pz2), cP)

        true ->
          IntegerUtils.modulo(3 * px * px + cA * pz2 * pz2, cP)
      end

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

    pz2 = IntegerUtils.modulo(pz * pz, cP)
    u2 = IntegerUtils.modulo(qx * pz2, cP)
    s2 = IntegerUtils.modulo(qy * pz2 * pz, cP)

    {u1, s1} =
      if qz == 1 do
        # Mixed affine+Jacobian add: qz^2 = qz^3 = 1 saves four multiplications.
        {px, py}
      else
        qz2 = IntegerUtils.modulo(qz * qz, cP)
        {IntegerUtils.modulo(px * qz2, cP), IntegerUtils.modulo(py * qz2 * qz, cP)}
      end

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
      nz =
        if qz == 1 do
          IntegerUtils.modulo(h * pz, cP)
        else
          IntegerUtils.modulo(h * pz * qz, cP)
        end

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

  # Shamir's trick with Joint Sparse Form (Solinas 2001). JSF picks
  # signed digits in {-1, 0, 1} so at most ~l/2 digit pairs are non-zero,
  # versus ~3l/4 for the raw binary form. Not constant-time -- use only
  # with public scalars (e.g. verification).
  defp shamirMultiply(jp1, n1, jp2, n2, cN, cA, cP) do
    n1 = if n1 < 0 or n1 >= cN, do: IntegerUtils.modulo(n1, cN), else: n1
    n2 = if n2 < 0 or n2 >= cN, do: IntegerUtils.modulo(n2, cN), else: n2

    if n1 == 0 and n2 == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      jp1p2 = jacobianAdd(jp1, jp2, cA, cP)
      jp1mp2 = jacobianAdd(jp1, neg(jp2, cP), cA, cP)

      addTable = %{
        {1, 0} => jp1,
        {-1, 0} => neg(jp1, cP),
        {0, 1} => jp2,
        {0, -1} => neg(jp2, cP),
        {1, 1} => jp1p2,
        {-1, -1} => neg(jp1p2, cP),
        {1, -1} => jp1mp2,
        {-1, 1} => neg(jp1mp2, cP)
      }

      digits = jsfDigits(n1, n2)
      r = %Point{x: 0, y: 0, z: 1}

      jsf_shamir_loop(r, digits, addTable, cA, cP)
    end
  end

  defp neg(%Point{y: 0} = p, _cP), do: p
  defp neg(p, cP), do: %Point{x: p.x, y: cP - p.y, z: p.z}

  defp jsf_shamir_loop(r, [], _addTable, _cA, _cP), do: r

  defp jsf_shamir_loop(r, [{0, 0} | rest], addTable, cA, cP) do
    r = jacobianDouble(r, cA, cP)
    jsf_shamir_loop(r, rest, addTable, cA, cP)
  end

  defp jsf_shamir_loop(r, [{u0, u1} | rest], addTable, cA, cP) do
    r = jacobianDouble(r, cA, cP)
    r = jacobianAdd(r, Map.fetch!(addTable, {u0, u1}), cA, cP)
    jsf_shamir_loop(r, rest, addTable, cA, cP)
  end

  # Joint Sparse Form of (k0, k1): list of signed-digit pairs (u0, u1) in
  # {-1, 0, 1}, ordered MSB-first. At most one of any two consecutive pairs
  # is non-zero, giving density ~1/2 instead of ~3/4 from raw binary.
  defp jsfDigits(k0, k1) do
    do_jsf(k0, k1, 0, 0, [])
  end

  defp do_jsf(k0, k1, d0, d1, acc) when k0 + d0 == 0 and k1 + d1 == 0, do: acc

  defp do_jsf(k0, k1, d0, d1, acc) do
    a0 = k0 + d0
    a1 = k1 + d1

    u0 =
      if (a0 &&& 1) == 1 do
        base = if (a0 &&& 3) == 1, do: 1, else: -1
        if (a0 &&& 7) in [3, 5] and (a1 &&& 3) == 2, do: -base, else: base
      else
        0
      end

    u1 =
      if (a1 &&& 1) == 1 do
        base = if (a1 &&& 3) == 1, do: 1, else: -1
        if (a1 &&& 7) in [3, 5] and (a0 &&& 3) == 2, do: -base, else: base
      else
        0
      end

    new_d0 = if 2 * d0 == 1 + u0, do: 1 - d0, else: d0
    new_d1 = if 2 * d1 == 1 + u1, do: 1 - d1, else: d1

    do_jsf(k0 >>> 1, k1 >>> 1, new_d0, new_d1, [{u0, u1} | acc])
  end

  # Compute n1*p1 + n2*p2 using the GLV endomorphism. Splits each 256-bit
  # scalar into two ~128-bit scalars via k = k1 + k2*lambda (mod N), then
  # runs a 4-scalar simultaneous double-and-add over (p1, phi(p1), p2, phi(p2))
  # with a 16-entry precomputed table of subset sums. Halves the loop
  # length versus the plain Shamir path.
  defp glvMultiplyAndAdd(p1, n1, p2, n2, curve) do
    glv = curve.glvParams
    cN = curve."N"
    cA = curve."A"
    cP = curve."P"
    beta = glv.beta

    {k1, k2} = glvDecompose(IntegerUtils.modulo(n1, cN), glv, cN)
    {k3, k4} = glvDecompose(IntegerUtils.modulo(n2, cN), glv, cN)

    # Base points (affine, z=1) -- phi((x,y)) = (beta*x mod P, y).
    bases = [
      %Point{x: p1.x, y: p1.y, z: 1},
      %Point{x: IntegerUtils.modulo(beta * p1.x, cP), y: p1.y, z: 1},
      %Point{x: p2.x, y: p2.y, z: 1},
      %Point{x: IntegerUtils.modulo(beta * p2.x, cP), y: p2.y, z: 1}
    ]

    scalars = [k1, k2, k3, k4]

    {bases, scalars} = absorbSigns(bases, scalars, cP)

    # Precompute table[idx] = sum of bases[i] selected by bits of idx.
    table = buildGlvTable(bases, cA, cP)

    maxLen = scalars |> Enum.map(&IntegerUtils.bit_length/1) |> Enum.max()
    [s0, s1, s2, s3] = scalars

    glv_loop(%Point{x: 0, y: 0, z: 1}, maxLen - 1, s0, s1, s2, s3, table, cA, cP)
  end

  defp glv_loop(r, bit, _s0, _s1, _s2, _s3, _table, _cA, _cP) when bit < 0, do: r

  defp glv_loop(r, bit, s0, s1, s2, s3, table, cA, cP) do
    r = jacobianDouble(r, cA, cP)

    idx =
      (s0 >>> bit &&& 1) |||
        ((s1 >>> bit &&& 1) <<< 1) |||
        ((s2 >>> bit &&& 1) <<< 2) |||
        ((s3 >>> bit &&& 1) <<< 3)

    r =
      if idx == 0 do
        r
      else
        jacobianAdd(r, elem(table, idx), cA, cP)
      end

    glv_loop(r, bit - 1, s0, s1, s2, s3, table, cA, cP)
  end

  # If scalar is negative, negate it and the corresponding base point.
  defp absorbSigns(bases, scalars, cP) do
    pairs =
      Enum.zip(bases, scalars)
      |> Enum.map(fn {b, s} ->
        if s < 0 do
          {%Point{x: b.x, y: cP - b.y, z: 1}, -s}
        else
          {b, s}
        end
      end)

    {Enum.map(pairs, &elem(&1, 0)), Enum.map(pairs, &elem(&1, 1))}
  end

  # Build a 16-entry table of subset sums over 4 base points, indexed by
  # the 4-bit selector. table[0] = infinity; table[idx] extends a smaller
  # subset by one base, keeping the construction at 15 adds total.
  defp buildGlvTable(bases, cA, cP) do
    bases_tuple = List.to_tuple(bases)
    zero = %Point{x: 0, y: 0, z: 1}

    Enum.reduce(1..15, {zero}, fn idx, acc ->
      low = idx &&& -idx
      i = IntegerUtils.bit_length(low) - 1
      prev = elem(acc, Bitwise.bxor(idx, low))
      Tuple.append(acc, jacobianAdd(prev, elem(bases_tuple, i), cA, cP))
    end)
  end

  # Decompose k into (k1, k2) with k = k1 + k2*lambda (mod N) and
  # |k1|, |k2| ~ sqrt(N). Babai rounding against the precomputed basis
  # {(a1, b1), (a2, b2)}; k1 and k2 may be negative.
  defp glvDecompose(k, glv, cN) do
    a1 = glv.a1
    b1 = glv.b1
    a2 = glv.a2
    b2 = glv.b2
    halfN = div(cN, 2)
    # Python uses floor division (//); in Elixir, div/2 truncates toward zero.
    # For these GLV expressions the dividend is non-negative (b1 is negative
    # in the constants so -b1*k is non-negative), so div == floor here.
    c1 = div(b2 * k + halfN, cN)
    c2 = div(-b1 * k + halfN, cN)
    k1 = k - c1 * a1 - c2 * a2
    k2 = -c1 * b1 - c2 * b2
    {k1, k2}
  end
end
