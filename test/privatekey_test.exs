defmodule PrivateKeyTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey}

  test "testPemConversion" do
    privateKey1 = PrivateKey.generate()

    pem = PrivateKey.toPem(privateKey1)

    {:ok, privateKey2} = PrivateKey.fromPem(pem)

    assert privateKey1.secret == privateKey2.secret
    assert privateKey1.curve == privateKey2.curve
  end

  test "testDerConversion" do
    privateKey1 = PrivateKey.generate()

    der = PrivateKey.toDer(privateKey1)

    {:ok, privateKey2} = PrivateKey.fromDer(der)

    assert privateKey1.secret == privateKey2.secret
    assert privateKey1.curve == privateKey2.curve
  end

  test "testStringConversion" do
    privateKey1 = PrivateKey.generate()

    string = PrivateKey.toString(privateKey1)

    {:ok, privateKey2} = PrivateKey.fromString(string)

    assert privateKey1.secret == privateKey2.secret
    assert privateKey1.curve == privateKey2.curve
  end
end
