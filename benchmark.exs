alias EllipticCurve.{PrivateKey, Ecdsa}

rounds = 100

privateKey = PrivateKey.generate()
publicKey = PrivateKey.getPublicKey(privateKey)
message = "This is a benchmark test message"

# Warmup
sig = Ecdsa.sign(message, privateKey)
Ecdsa.verify?(message, sig, publicKey)

# Benchmark sign
start = System.monotonic_time(:millisecond)

sig =
  Enum.reduce(1..rounds, nil, fn _, _acc ->
    Ecdsa.sign(message, privateKey)
  end)

sign_time = (System.monotonic_time(:millisecond) - start) / rounds

# Benchmark verify
start = System.monotonic_time(:millisecond)

Enum.each(1..rounds, fn _ ->
  Ecdsa.verify?(message, sig, publicKey)
end)

verify_time = (System.monotonic_time(:millisecond) - start) / rounds

IO.puts("")
IO.puts("starkbank-ecdsa benchmark (#{rounds} rounds)")
IO.puts("---------------------------------------")
IO.puts("sign:    #{:erlang.float_to_binary(sign_time / 1, decimals: 1)}ms")
IO.puts("verify:  #{:erlang.float_to_binary(verify_time / 1, decimals: 1)}ms")
IO.puts("")
