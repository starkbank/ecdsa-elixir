defmodule Ellipticcurve.MixProject do
  use Mix.Project

  def project do
    [
      app: :starkbank_ecdsa,
      name: :starkbank_ecdsa,
      version: "1.1.0",
      homepage_url: "https://starkbank.com",
      source_url: "https://github.com/starkbank/ecdsa-elixir",
      description: description(),
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package()
    ]
  end

  defp package do
    [
      maintainers: ["Stark Bank"],
      licenses: [:MIT],
      links: %{
        "StarkBank" => "https://starkbank.com",
        "GitHub" => "https://github.com/starkbank/ecdsa-elixir"
      }
    ]
  end

  defp description do
    "A lightweight and fast pure Elixir ECDSA library."
  end

  def application do
    [extra_applications: [:crypto]]
  end

  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
