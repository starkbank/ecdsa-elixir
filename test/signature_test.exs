defmodule SignatureTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa, Signature}

  test "der conversion" do
    privateKey = PrivateKey.generate()
    message = "This is a text message"

    signature1 = Ecdsa.sign(message, privateKey)

    der = Signature.toDer(signature1)
    {:ok, signature2} = Signature.fromDer(der)

    assert signature1.r == signature2.r
    assert signature1.s == signature2.s
  end

  test "base64 conversion" do
    privateKey = PrivateKey.generate()
    message = "This is a text message"

    signature1 = Ecdsa.sign(message, privateKey)

    base64 = Signature.toBase64(signature1)

    {:ok, signature2} = Signature.fromBase64(base64)

    assert signature1.r == signature2.r
    assert signature1.s == signature2.s
  end
end
