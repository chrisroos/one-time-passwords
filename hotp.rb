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
    key.chars.map { |chr| '\x' + chr.ord.to_s(16) }.join
  end

  def counter_to_hex(counter)
    hex = counter.to_s(16)
    padded_to_8_bytes = hex.rjust(16, '0')
    bytes = padded_to_8_bytes.scan(/\d\d/)
    bytes.map { |hex_byte| '\x' + hex_byte }.join
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
    expected_hex_key = '\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30'
    assert_equal expected_hex_key, Hotp.new.key_to_hex(key)
  end

  def test_should_convert_counter_to_8_byte_hex_string
    counter = 0
    expected_hex_string = '\x00\x00\x00\x00\x00\x00\x00\x00'
    assert_equal expected_hex_string, Hotp.new.counter_to_hex(counter)
  end

  def test_should_match_hmacs_from_test_data_in_rfc_4226
    key = "12345678901234567890"
    digest = OpenSSL::Digest.new('sha1')
    [
      ["\x00\x00\x00\x00\x00\x00\x00\x00", 'cc93cf18508d94934c64b65d8ba7667fb7cde4b0'],
      ["\x00\x00\x00\x00\x00\x00\x00\x01", '75a48a19d4cbe100644e8ac1397eea747a2d33ab'],
      ["\x00\x00\x00\x00\x00\x00\x00\x02", '0bacb7fa082fef30782211938bc1c5e70416ff44'],
      ["\x00\x00\x00\x00\x00\x00\x00\x03", '66c28227d03a2d5529262ff016a1e6ef76557ece'],
      ["\x00\x00\x00\x00\x00\x00\x00\x04", 'a904c900a64b35909874b33e61c5938a8e15ed1c'],
      ["\x00\x00\x00\x00\x00\x00\x00\x05", 'a37e783d7b7233c083d4f62926c7a25f238d0316'],
      ["\x00\x00\x00\x00\x00\x00\x00\x06", 'bc9cd28561042c83f219324d3c607256c03272ae'],
      ["\x00\x00\x00\x00\x00\x00\x00\x07", 'a4fb960c0bc06e1eabb804e5b397cdc4b45596fa'],
      ["\x00\x00\x00\x00\x00\x00\x00\x08", '1b3c89f65e6c9e883012052823443f048b4332db'],
      ["\x00\x00\x00\x00\x00\x00\x00\x09", '1637409809a679dc698207310c8c7fc07290d9e5']
    ].each do |(counter, expected_hmac)|
      hmac = OpenSSL::HMAC.hexdigest(digest, key, counter)
      assert_equal expected_hmac, hmac
    end
  end

end
