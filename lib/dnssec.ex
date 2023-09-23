defmodule DNSSEC do
  @moduledoc """
  Documentation for `DNSSEC`.
  """

  @doc """
  Turns a binary DNSKEY RR into a tuple representation

                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |              Flags            |    Protocol   |   Algorithm   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      /                                                               /
      /                            Public Key                         /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  ## Examples

      iex> key1 = DNSSEC.dnskey_from_binary(<<1,0,3,13,242,30,156,252,222,57,116,223,132,191,19,155,37,12,64,136,235,7,
      iex> 131,136,123,28,153,210,101,48,230,44,0,176,186,246,212,11,224,101,101,32,
      iex> 177,35,160,0,130,237,220,125,167,162,139,140,23,189,73,59,110,219,144,41,68,
      iex> 80,220,44,123,66>>)
      iex> ^key1 = {256, 3, 13, "8h6c/N45dN+EvxObJQxAiOsHg4h7HJnSZTDmLACwuvbUC+BlZSCxI6AAgu3cfaeii4wXvUk7btuQKURQ3Cx7Qg=="}
      iex> key2 = DNSSEC.dns_key_from_binary(<<1,1,3,13,10,191,218,31,120,61,229,200,246,58,127,56,155,139,113,10,183,53,
      iex> 177,21,243,105,205,47,43,139,93,124,171,22,121,111,80,21,80,48,141,255,23,
      iex> 143,120,77,132,41,97,60,101,79,71,20,250,34,81,11,182,120,9,189,3,192,244,
      iex> 115,195,122>>)
      iex> ^key2 = {257, 3, 13, "Cr/aH3g95cj2On84m4txCrc1sRXzac0vK4tdfKsWeW9QFVAwjf8Xj3hNhClhPGVPRxT6IlELtngJvQPA9HPDeg=="}

  """
  def dnskey_from_binary(<<flags::16, proto::8, algo::8, pubkey::binary>>) do
    {flags, proto, algo, Base.encode64(pubkey)}
  end

  @doc """
  Turns a binary DS RR into a tuple representation

                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Key Tag             |  Algorithm    |  Digest Type  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      /                                                               /
      /                            Digest                             /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  ## Examples

      iex> ds1 = DNSSEC.ds_from_binary(<<182,109,13,2,84,90,134,83,213,246,40,71,56,114,171,180,92,250,81,149,89,215,
      iex> 66,174,110,80,221,124,99,57,208,129,148,103,237,246>>)
      iex> ^ds1 = {46701, 13, 2, "VFqGU9X2KEc4cqu0XPpRlVnXQq5uUN18YznQgZRn7fY="}
      iex> ds2 = DNSSEC.ds_from_binary(<<182,109,13,4,229,96,182,230,225,253,99,254,59,131,182,188,145,111,2,205,
      iex> 118,251,19,90,219,59,70,106,213,78,193,167,221,157,196,254,177,137,182,247,
      iex> 65,212,103,231,164,234,239,229,105,145,116,129>>)
      iex> ^ds2 = {46701, 13, 4, "5WC25uH9Y/47g7a8kW8CzXb7E1rbO0Zq1U7Bp92dxP6xibb3QdRn56Tq7+VpkXSB"}
  """
  def ds_from_binary(<<type::16, algo::8, digest_type::8, digest::binary>>) do
    {type, algo, digest_type, Base.encode64(digest)}
  end

  def ds_algorithm(algo) do
    case algo do
      1 -> :sha1
      _ -> raise "unassigned"
    end
  end

  @doc """
  Calculates the keytag for a given DNSKEY in binary form.

  RFC 4034 describes the keytag calculation in (Appendix B.1)[https://www.rfc-editor.org/rfc/rfc4034#appendix-B.1]

  ## Examples

      iex> 46701 = DNSSEC.keytag(<<1,1,3,13,10,191,218,31,120,61,229,200,246,58,127,56,155,139,113,10,183,53,
      iex> 177,21,243,105,205,47,43,139,93,124,171,22,121,111,80,21,80,48,141,255,23,
      iex> 143,120,77,132,41,97,60,101,79,71,20,250,34,81,11,182,120,9,189,3,192,244,
      iex> 115,195,122>>)
  """
  def keytag(key_rdata) when is_binary(key_rdata) do
    import Bitwise

    key_rdata
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.reduce(0, fn {char, i}, acc ->
      acc + if rem(i, 2) == 0, do: char <<< 8, else: char
    end)
    |> then(fn ac -> ac + (ac >>> 16) &&& 0xFFFF &&& 0xFFFF end)
  end

  @doc """
  DNS Record type for DNSKEY
  """
  def dnskey_type(), do: 48

  @doc """
  DNS Record type for DS
  """
  def ds_type(), do: 43
end
