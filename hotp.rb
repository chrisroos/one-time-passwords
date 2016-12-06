require 'openssl'

class Hotp
  # string = 20 byte binary string
  def dynamic_truncation(string)
    bytes_in_string = string.bytes.length
    p ['bytes_in_string', bytes_in_string] # RFC says this should be 20 bytes

    # Let OffsetBits be the low-order 4 bits of String[19]
    last_byte = string.bytes.last
    p ['last_byte', last_byte]
    last_byte_as_hex = last_byte.to_s(16)
    p ['last_byte_as_hex', last_byte_as_hex]
    last_byte_as_binary = last_byte.to_s(2).rjust(8, '0')
    p ['last_byte_as_binary', last_byte_as_binary]
    offset_bits = last_byte_as_binary[4..7]
    p ['offset_bits', offset_bits]

    # Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
    offset = offset_bits.to_i(2)
    p ['offset', offset]

    # Let P = String[OffSet]...String[OffSet+3]
    pee = string[offset..offset + 3]
    p ['pee', pee]
    bytes_in_pee = pee.bytes.length
    p ['bytes_in_pee', bytes_in_pee]

    # Return the Last 31 bits of P
    pee_in_binary = pee.bytes.map { |b| b.to_s(2).rjust(8, '0') }.join
    p ['pee_in_binary', pee_in_binary]

    last_31_bits_of_pee = pee_in_binary[1..31]
    p ['last_31_bits_of_pee', last_31_bits_of_pee]
    last_31_bits_of_pee
  end

  def hmac(key, counter)
    digest = OpenSSL::Digest.new('sha1')
    hmac = OpenSSL::HMAC.digest(digest, key, counter.to_s)
  end

  def hotp(hmac, digits)
    sbits = dynamic_truncation(hmac)
    p ['sbits', sbits]

    snum = sbits.to_i(2)
    p ['snum', snum]

    dee = snum.modulo(10 ** digits)
    p ['dee', dee]
    dee
  end

  def key_to_hex(key)
    "0x" + key.chars.map { |chr| chr.ord.to_s(16) }.join
  end
end

require 'test/unit'

class HotpTest < Test::Unit::TestCase
  def test_should_match_otp_from_rfc_4226
    hmac = "\x1f\x86\x98\x69\x0e\x02\xca\x16\x61\x85\x50\xef\x7f\x19\xda\x8e\x94\x5b\x55\x5a"
    assert_equal 872921, Hotp.new.hotp(hmac, 6)
  end

  def test_should_convert_secret_to_hex
    key = '12345678901234567890'
    expected_hex_key = '0x3132333435363738393031323334353637383930'
    assert_equal expected_hex_key, Hotp.new.key_to_hex(key)
  end

end
