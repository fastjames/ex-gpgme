defmodule ExGpgme.Results.VerificationResult do
  @moduledoc """
  Verification Result
  """

  alias ExGpgme.Results.Signature

  @enforce_keys [
    :filename,
    :signatures
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          filename: String.t() | nil,
          signatures: [Signature.t()]
        }
end
