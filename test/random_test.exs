defmodule RandomTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, PublicKey, Ecdsa, Signature}

  @tag timeout: 600_000
  test "testMany" do
    Enum.each(1..100, fn _ ->
      privateKey1 = PrivateKey.generate()
      publicKey1 = PrivateKey.getPublicKey(privateKey1)

      privateKeyPem = PrivateKey.toPem(privateKey1)
      publicKeyPem = PublicKey.toPem(publicKey1)

      {:ok, privateKey2} = PrivateKey.fromPem(privateKeyPem)
      {:ok, publicKey2} = PublicKey.fromPem(publicKeyPem)

      message = "test"

      signatureBase64 = Ecdsa.sign(message, privateKey2) |> Signature.toBase64()
      {:ok, signature} = Signature.fromBase64(signatureBase64)

      assert Ecdsa.verify?(message, signature, publicKey2)
    end)
  end
end
