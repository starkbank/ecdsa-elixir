defmodule EcdsaTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Signature, Ecdsa}

  test "testVerifyRightMessage" do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)

    message = "This is the right message"

    signature = Ecdsa.sign(message, privateKey)

    assert Ecdsa.verify?(message, signature, publicKey)
  end

  test "testVerifyWrongMessage" do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)

    message1 = "This is the right message"
    message2 = "This is the wrong message"

    signature = Ecdsa.sign(message1, privateKey)

    refute Ecdsa.verify?(message2, signature, publicKey)
  end

  test "testZeroSignature" do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)

    message = "This is the wrong message"

    refute Ecdsa.verify?(message, %Signature{r: 0, s: 0}, publicKey)
  end
end
