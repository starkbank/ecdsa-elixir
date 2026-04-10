defmodule EllipticCurve.Curve.KnownCurves do
  @moduledoc """
  Describes the elliptic curves supported by the package.
  Supports dynamic curve registration via add/1 and lookup via getByOid/1.
  """

  alias EllipticCurve.{Curve, Point}

  use Agent

  def start_link(_opts \\ []) do
    case Agent.start_link(fn -> initial_curves() end, name: __MODULE__) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
    end
  end

  defp ensure_started do
    case Process.whereis(__MODULE__) do
      nil -> start_link()
      _pid -> :ok
    end
  end

  defp initial_curves do
    s = secp256k1()
    p = prime256v1()
    %{
      s.oid => s,
      p.oid => p
    }
  end

  @doc """
  Register a new curve (matching Python's curve.add()).
  """
  def add(curve) do
    ensure_started()
    Agent.update(__MODULE__, fn curves ->
      Map.put(curves, curve.oid, curve)
    end)
  end

  @doc """
  Look up a curve by its OID list (matching Python's curve.getByOid()).
  """
  def getByOid(oid) do
    ensure_started()
    Agent.get(__MODULE__, fn curves ->
      Map.get(curves, oid)
    end)
    |> case do
      nil -> raise "Unknown curve with oid #{inspect(oid)}"
      curve -> curve
    end
  end

  def getCurveByOid(oid) do
    getByOid(oid)
  end

  def getCurveByName(name) do
    case name do
      :secp256k1 -> secp256k1()
      :prime256v1 -> prime256v1()
      name when is_binary(name) ->
        case name do
          "secp256k1" -> secp256k1()
          "prime256v1" -> prime256v1()
          _ -> raise "Unknown curve: #{name}"
        end
      _ -> raise "Unknown curve: #{inspect(name)}"
    end
  end

  def secp256k1 do
    %Curve{
      name: :secp256k1,
      A: 0x0000000000000000000000000000000000000000000000000000000000000000,
      B: 0x0000000000000000000000000000000000000000000000000000000000000007,
      P: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
      N: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
      G: %Point{
        x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
      },
      oid: [1, 3, 132, 0, 10]
    }
  end

  def prime256v1 do
    %Curve{
      name: :prime256v1,
      nistName: "P-256",
      A: 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
      B: 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
      P: 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
      N: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
      G: %Point{
        x: 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        y: 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
      },
      oid: [1, 2, 840, 10045, 3, 1, 7]
    }
  end
end
