defmodule ExGpgme.Results.Import do
  @moduledoc """
  Import struct for any key in an import.
  """

  @enforce_keys [
    :fingerprint
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          fingerprint: String.t()
        }
end
