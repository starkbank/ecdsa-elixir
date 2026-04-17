defmodule Prime256v1PublicKeyDerivationTest do
  @moduledoc """
  RFC 6979 A.2.5 public key derivation. Signatures are hedged, so r/s
  no longer match fixed test vectors, but pubkey derivation is unchanged.
  """
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa}
  alias EllipticCurve.Curve.KnownCurves

  setup do
    curve = KnownCurves.prime256v1()
    privateKey = PrivateKey.generate(
      0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
      curve
    )
    publicKey = PrivateKey.getPublicKey(privateKey)
    %{privateKey: privateKey, publicKey: publicKey, curve: curve}
  end

  test "testPublicKeyMatchesRfc", %{publicKey: publicKey} do
    assert publicKey.point.x == 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
    assert publicKey.point.y == 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
  end

  test "testSampleMessageRoundTrip", %{privateKey: privateKey, publicKey: publicKey, curve: curve} do
    sig = Ecdsa.sign("sample", privateKey)
    assert sig.s <= div(curve."N", 2)
    assert Ecdsa.verify?("sample", sig, publicKey)
  end

  test "testTestMessageRoundTrip", %{privateKey: privateKey, publicKey: publicKey, curve: curve} do
    sig = Ecdsa.sign("test", privateKey)
    assert sig.s <= div(curve."N", 2)
    assert Ecdsa.verify?("test", sig, publicKey)
  end
end

defmodule Secp256k1PublicKeyDerivationTest do
  @moduledoc """
  secp256k1 with secret=1 (pubkey = generator G).
  """
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa}
  alias EllipticCurve.Curve.KnownCurves

  setup do
    curve = KnownCurves.secp256k1()
    privateKey = PrivateKey.generate(1, curve)
    publicKey = PrivateKey.getPublicKey(privateKey)
    %{privateKey: privateKey, publicKey: publicKey, curve: curve}
  end

  test "testPublicKeyIsGenerator", %{publicKey: publicKey, curve: curve} do
    assert publicKey.point.x == curve."G".x
    assert publicKey.point.y == curve."G".y
  end

  test "testSampleMessageRoundTrip", %{privateKey: privateKey, publicKey: publicKey} do
    sig = Ecdsa.sign("sample", privateKey)
    assert Ecdsa.verify?("sample", sig, publicKey)
  end

  test "testTestMessageRoundTrip", %{privateKey: privateKey, publicKey: publicKey} do
    sig = Ecdsa.sign("test", privateKey)
    assert Ecdsa.verify?("test", sig, publicKey)
  end
end

defmodule MalleabilityTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa, Signature}

  test "testSignAlwaysProducesLowS" do
    Enum.each(1..100, fn _ ->
      privateKey = PrivateKey.generate()
      signature = Ecdsa.sign("test message", privateKey)
      assert signature.s <= div(privateKey.curve."N", 2)
    end)
  end

  test "testHighSSignatureStillVerifies" do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)
    message = "test message"

    signature = Ecdsa.sign(message, privateKey)
    highS = %Signature{r: signature.r, s: privateKey.curve."N" - signature.s}

    assert Ecdsa.verify?(message, signature, publicKey)
    assert Ecdsa.verify?(message, highS, publicKey)
  end
end

defmodule PublicKeyValidationTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, PublicKey, Ecdsa, Point, Curve}
  alias EllipticCurve.Curve.KnownCurves
  alias EllipticCurve.Utils.Integer, as: IntegerUtils

  test "testRejectOffCurvePublicKey" do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)
    message = "test message"

    signature = Ecdsa.sign(message, privateKey)

    offCurvePoint = %Point{x: publicKey.point.x, y: publicKey.point.y + 1}
    offCurveKey = %PublicKey{point: offCurvePoint, curve: publicKey.curve}

    refute Ecdsa.verify?(message, signature, offCurveKey)
  end

  test "testFromStringRejectsOffCurvePoint" do
    p = PrivateKey.generate() |> PrivateKey.getPublicKey()
    baseLength = Curve.getLength(p.curve)
    badY = p.point.y + 1

    badYString =
      badY
      |> Integer.to_string(16)
      |> String.pad_leading(baseLength * 2, "0")
      |> Base.decode16!(case: :mixed)

    goodXString =
      p.point.x
      |> Integer.to_string(16)
      |> String.pad_leading(baseLength * 2, "0")
      |> Base.decode16!(case: :mixed)

    # Pad to exactly baseLength bytes
    goodXString = String.pad_leading(goodXString, baseLength, <<0>>)
    badYString = String.pad_leading(badYString, baseLength, <<0>>)

    badHex = goodXString <> badYString

    assert_raise RuntimeError, fn ->
      PublicKey.fromString!(badHex, p.curve)
    end
  end

  test "testFromStringRejectsInfinityPoint" do
    curve = KnownCurves.secp256k1()
    baseLength = Curve.getLength(curve)
    zeroHex = String.duplicate(<<0>>, 2 * baseLength)

    assert_raise RuntimeError, fn ->
      PublicKey.fromString!(zeroHex, curve)
    end
  end
end

defmodule ForgeryAttemptTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa, Signature}

  setup do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)
    message = "authentic message"
    signature = Ecdsa.sign(message, privateKey)
    %{privateKey: privateKey, publicKey: publicKey, message: message, signature: signature}
  end

  test "testRejectZeroSignature", %{message: message, publicKey: publicKey} do
    refute Ecdsa.verify?(message, %Signature{r: 0, s: 0}, publicKey)
  end

  test "testRejectREqualsZero", %{message: message, publicKey: publicKey, signature: signature} do
    refute Ecdsa.verify?(message, %Signature{r: 0, s: signature.s}, publicKey)
  end

  test "testRejectSEqualsZero", %{message: message, publicKey: publicKey, signature: signature} do
    refute Ecdsa.verify?(message, %Signature{r: signature.r, s: 0}, publicKey)
  end

  test "testRejectREqualsN", %{message: message, publicKey: publicKey, signature: signature} do
    n = publicKey.curve."N"
    refute Ecdsa.verify?(message, %Signature{r: n, s: signature.s}, publicKey)
  end

  test "testRejectSEqualsN", %{message: message, publicKey: publicKey, signature: signature} do
    n = publicKey.curve."N"
    refute Ecdsa.verify?(message, %Signature{r: signature.r, s: n}, publicKey)
  end

  test "testRejectRExceedsN", %{message: message, publicKey: publicKey, signature: signature} do
    n = publicKey.curve."N"
    refute Ecdsa.verify?(message, %Signature{r: n + 1, s: signature.s}, publicKey)
  end

  test "testRejectArbitrarySignature", %{message: message, publicKey: publicKey} do
    refute Ecdsa.verify?(message, %Signature{r: 1, s: 1}, publicKey)
  end

  test "testRejectBoundarySignature", %{message: message, publicKey: publicKey} do
    n = publicKey.curve."N"
    refute Ecdsa.verify?(message, %Signature{r: n - 1, s: n - 1}, publicKey)
  end

  test "testWrongKeyRejected", %{message: message, signature: signature} do
    otherKey = PrivateKey.generate() |> PrivateKey.getPublicKey()
    refute Ecdsa.verify?(message, signature, otherKey)
  end
end

defmodule HedgedSignatureTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa}

  test "testSameInputsProduceDifferentSignatures" do
    privateKey = PrivateKey.generate()
    message = "test message"

    signature1 = Ecdsa.sign(message, privateKey)
    signature2 = Ecdsa.sign(message, privateKey)

    assert signature1.r != signature2.r or signature1.s != signature2.s
  end

  test "testDifferentMessagesDifferentSignatures" do
    privateKey = PrivateKey.generate()

    signature1 = Ecdsa.sign("message 1", privateKey)
    signature2 = Ecdsa.sign("message 2", privateKey)

    assert signature1.r != signature2.r or signature1.s != signature2.s
  end

  test "testDifferentKeysDifferentSignatures" do
    message = "test message"

    signature1 = Ecdsa.sign(message, PrivateKey.generate())
    signature2 = Ecdsa.sign(message, PrivateKey.generate())

    assert signature1.r != signature2.r or signature1.s != signature2.s
  end
end

defmodule EdgeCaseMessageTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa}

  setup do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)
    %{privateKey: privateKey, publicKey: publicKey}
  end

  defp sign_and_verify(message, privateKey, publicKey) do
    sig = Ecdsa.sign(message, privateKey)
    assert Ecdsa.verify?(message, sig, publicKey)
    refute Ecdsa.verify?(message <> "x", sig, publicKey)
  end

  test "testEmptyMessage", %{privateKey: pk, publicKey: pub} do
    sign_and_verify("", pk, pub)
  end

  test "testSingleCharMessage", %{privateKey: pk, publicKey: pub} do
    sign_and_verify("a", pk, pub)
  end

  test "testUnicodeMessage", %{privateKey: pk, publicKey: pub} do
    sign_and_verify("\u00e9\u00e8\u00ea\u00eb", pk, pub)
  end

  test "testEmojiMessage", %{privateKey: pk, publicKey: pub} do
    sign_and_verify("\u{1F512}\u{1F511}", pk, pub)
  end

  test "testNullByteMessage", %{privateKey: pk, publicKey: pub} do
    sign_and_verify("before\x00after", pk, pub)
  end

  test "testLongMessage", %{privateKey: pk, publicKey: pub} do
    sign_and_verify(String.duplicate("a", 10000), pk, pub)
  end

  test "testNewlinesAndWhitespace", %{privateKey: pk, publicKey: pub} do
    sign_and_verify("  line1\n\tline2\r\n  ", pk, pub)
  end
end

defmodule SerializationRoundTripTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, PublicKey, Ecdsa, Signature}
  alias EllipticCurve.Curve.KnownCurves

  setup do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)
    message = "round-trip test"
    signature = Ecdsa.sign(message, privateKey)
    %{privateKey: privateKey, publicKey: publicKey, message: message, signature: signature}
  end

  test "testSignatureDerRoundTrip", %{signature: signature, message: message, publicKey: publicKey} do
    der = Signature.toDer(signature)
    {:ok, restored} = Signature.fromDer(der)
    assert restored.r == signature.r
    assert restored.s == signature.s
    assert Ecdsa.verify?(message, restored, publicKey)
  end

  test "testSignatureBase64RoundTrip", %{signature: signature, message: message, publicKey: publicKey} do
    b64 = Signature.toBase64(signature)
    {:ok, restored} = Signature.fromBase64(b64)
    assert restored.r == signature.r
    assert restored.s == signature.s
    assert Ecdsa.verify?(message, restored, publicKey)
  end

  test "testSignatureDerWithRecoveryIdRoundTrip", %{signature: signature} do
    der = Signature.toDer(signature, withRecoveryId: true)
    {:ok, restored} = Signature.fromDer(der, recoveryByte: true)
    assert restored.r == signature.r
    assert restored.s == signature.s
    assert restored.recoveryId == signature.recoveryId
  end

  test "testPrivateKeyPemRoundTrip", %{privateKey: privateKey} do
    pem = PrivateKey.toPem(privateKey)
    {:ok, restored} = PrivateKey.fromPem(pem)
    assert restored.secret == privateKey.secret
    assert restored.curve.name == privateKey.curve.name
  end

  test "testPrivateKeyDerRoundTrip", %{privateKey: privateKey} do
    der = PrivateKey.toDer(privateKey)
    {:ok, restored} = PrivateKey.fromDer(der)
    assert restored.secret == privateKey.secret
  end

  test "testPublicKeyPemRoundTrip", %{publicKey: publicKey} do
    pem = PublicKey.toPem(publicKey)
    {:ok, restored} = PublicKey.fromPem(pem)
    assert restored.point.x == publicKey.point.x
    assert restored.point.y == publicKey.point.y
  end

  test "testPublicKeyCompressedRoundTrip", %{publicKey: publicKey, message: message, signature: signature} do
    compressed = PublicKey.toCompressed(publicKey)
    restored = PublicKey.fromCompressed(compressed, publicKey.curve)
    assert restored.point.x == publicKey.point.x
    assert restored.point.y == publicKey.point.y
    assert Ecdsa.verify?(message, signature, restored)
  end

  test "testPublicKeyCompressedEvenAndOdd" do
    Enum.each(1..20, fn _ ->
      pk = PrivateKey.generate()
      pub = PrivateKey.getPublicKey(pk)
      compressed = PublicKey.toCompressed(pub)
      restored = PublicKey.fromCompressed(compressed, pub.curve)
      assert restored.point.x == pub.point.x
      assert restored.point.y == pub.point.y
    end)
  end

  test "testPrime256v1KeyRoundTrip" do
    pk = PrivateKey.generate(nil, KnownCurves.prime256v1())
    pem = PrivateKey.toPem(pk)
    {:ok, restored} = PrivateKey.fromPem(pem)
    assert restored.secret == pk.secret
    assert restored.curve.name == :prime256v1
  end
end

defmodule TonelliShanksTest do
  use ExUnit.Case

  alias EllipticCurve.Math

  test "testPrimeCongruent1Mod4" do
    # P = 17: 17 - 1 = 16 = 2^4, S = 4, exercises full Tonelli-Shanks
    p = 17
    Enum.each(1..(p - 1), fn value ->
      if :crypto.mod_pow(<<value>>, <<div(p - 1, 2)>>, <<p>>) |> :binary.decode_unsigned() == 1 do
        root = Math.modularSquareRoot(value, p)
        assert rem(root * root, p) == value
      end
    end)
  end

  test "testPrimeCongruent5Mod8" do
    # P = 13: 13 - 1 = 12 = 3 * 2^2, S = 2
    p = 13
    Enum.each(1..(p - 1), fn value ->
      if :crypto.mod_pow(<<value>>, <<div(p - 1, 2)>>, <<p>>) |> :binary.decode_unsigned() == 1 do
        root = Math.modularSquareRoot(value, p)
        assert rem(root * root, p) == value
      end
    end)
  end

  test "testPrimeCongruent3Mod4" do
    # P = 7: fast path (S = 1)
    p = 7
    Enum.each(1..(p - 1), fn value ->
      if :crypto.mod_pow(<<value>>, <<div(p - 1, 2)>>, <<p>>) |> :binary.decode_unsigned() == 1 do
        root = Math.modularSquareRoot(value, p)
        assert rem(root * root, p) == value
      end
    end)
  end

  test "testZeroValue" do
    assert Math.modularSquareRoot(0, 17) == 0
  end
end

defmodule HashTruncationTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa}

  test "testSignVerifyWithSha512" do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)
    message = "test message"

    signature = Ecdsa.sign(message, privateKey, hashfunc: :sha512)

    assert Ecdsa.verify?(message, signature, publicKey, hashfunc: :sha512)
    refute Ecdsa.verify?("wrong message", signature, publicKey, hashfunc: :sha512)
  end

  test "testSha512SignaturesAreHedged" do
    privateKey = PrivateKey.generate()
    message = "test message"

    signature1 = Ecdsa.sign(message, privateKey, hashfunc: :sha512)
    signature2 = Ecdsa.sign(message, privateKey, hashfunc: :sha512)

    assert signature1.r != signature2.r or signature1.s != signature2.s
  end

  test "testHashMismatchFails" do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)
    message = "test message"

    signature = Ecdsa.sign(message, privateKey, hashfunc: :sha256)
    refute Ecdsa.verify?(message, signature, publicKey, hashfunc: :sha512)
  end
end

defmodule Prime256v1SecurityTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa}
  alias EllipticCurve.Curve.KnownCurves

  test "testSignVerify" do
    curve = KnownCurves.prime256v1()
    privateKey = PrivateKey.generate(nil, curve)
    publicKey = PrivateKey.getPublicKey(privateKey)
    message = "test message"

    signature = Ecdsa.sign(message, privateKey)

    assert signature.s <= div(curve."N", 2)
    assert Ecdsa.verify?(message, signature, publicKey)
  end

  test "testSignaturesAreHedged" do
    curve = KnownCurves.prime256v1()
    privateKey = PrivateKey.generate(nil, curve)
    message = "test message"

    signature1 = Ecdsa.sign(message, privateKey)
    signature2 = Ecdsa.sign(message, privateKey)

    assert signature1.r != signature2.r or signature1.s != signature2.s
  end

  test "testWrongCurveKeyFails" do
    k1Key = PrivateKey.generate(nil, KnownCurves.secp256k1())
    p256Key = PrivateKey.generate(nil, KnownCurves.prime256v1())
    message = "cross-curve test"

    sig = Ecdsa.sign(message, k1Key)
    refute Ecdsa.verify?(message, sig, PrivateKey.getPublicKey(p256Key))
  end
end
