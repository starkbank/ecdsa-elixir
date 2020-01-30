defmodule Ellipticcurve.MixProject do
  use Mix.Project

  def project do
    [
      app: :starkbank_ecdsa,
      version: "0.0.1",
      elixir: "~> 1.9",
      deps: deps()
    ]
  end

  def application do
    []
  end

  defp deps do
    []
  end
end
