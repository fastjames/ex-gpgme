defmodule ExGpgme.Mixfile do
  @moduledoc false

  use Mix.Project

  def project do
    [
      aliases: aliases(),
      app: :ex_gpgme,
      version: "0.1.3",
      elixir: "~> 1.11",
      start_permanent: Mix.env == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      compilers: Mix.compilers,
      rustler_crates: rustler_crates(),
      dialyzer: [ignore_warnings: "dialyzer.ignore-warnings"],
      test_coverage: [tool: ExCoveralls]
    ]
  end

  defp description do
    """
    Elixir NIF wrapper for `gpgme`.
    """
  end

  defp package do
    [
      name: :ex_gpgme,
      files: ["lib", "mix.exs", "README*", "LICENSE", "native"],
      maintainers: ["airatel Inc.", "Jonatan Männchen"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/jshmrtn/ex-gpgme"}
    ]
  end

  defp aliases do
    [
      check: [
        "clean",
        "deps.unlock --check-unused",
        "compile --warnings-as-errors",
        "format --check-formatted",
        "deps.unlock --check-unused",
        "test",
        "credo"
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.25.0"},
      {:ex_doc, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:inch_ex, ">= 0.0.0", only: :docs, runtime: false},
      {:credo, "~> 1.0", only: [:dev, :test], runtime: false},
      {:credo_contrib, "~> 0.2.0", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.14.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp rustler_crates do
    [
      exgpgme: [
        path: "native/exgpgme",
        mode: (if Mix.env == :prod, do: :release, else: :debug),
      ],
    ]
  end
end
