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
    hmac = OpenSSL::HMAC.hexdigest(digest, key, counter_to_hex(counter))
  end

  def hotp(hmac, digits)
    sbits = dynamic_truncation(hmac)
    p ['sbits', sbits]

    snum = sbits.to_i(2)
    p ['snum', snum]
    p ['snum as hex', snum.to_s(16)]

    dee = snum.modulo(10 ** digits)
    p ['dee', dee]
    dee
  end

  def key_to_hex(key)
    key.chars.map { |chr| '\x' + chr.ord.to_s(16) }.join
  end

  def counter_to_hex(counter)
    [counter].pack('Q>')
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
    expected_hex_string = "\x00\x00\x00\x00\x00\x00\x00\x00"
    assert_equal expected_hex_string, Hotp.new.counter_to_hex(counter)
  end

  def test_should_match_hmacs_from_test_data_in_rfc_4226
    key = "12345678901234567890"
    hotp = Hotp.new
    [
      [0, 'cc93cf18508d94934c64b65d8ba7667fb7cde4b0'],
      [1, '75a48a19d4cbe100644e8ac1397eea747a2d33ab'],
      [2, '0bacb7fa082fef30782211938bc1c5e70416ff44'],
      [3, '66c28227d03a2d5529262ff016a1e6ef76557ece'],
      [4, 'a904c900a64b35909874b33e61c5938a8e15ed1c'],
      [5, 'a37e783d7b7233c083d4f62926c7a25f238d0316'],
      [6, 'bc9cd28561042c83f219324d3c607256c03272ae'],
      [7, 'a4fb960c0bc06e1eabb804e5b397cdc4b45596fa'],
      [8, '1b3c89f65e6c9e883012052823443f048b4332db'],
      [9, '1637409809a679dc698207310c8c7fc07290d9e5']
    ].each do |(counter, expected_hmac)|
      hmac = hotp.hmac(key, counter)
      assert_equal expected_hmac, hmac
    end
  end

  def test_should_match_hotps_from_test_data_in_rfc_4226
    hotp = Hotp.new
    [
      ["\xcc\x93\xcf\x18\x50\x8d\x94\x93\x4c\x64\xb6\x5d\x8b\xa7\x66\x7f\xb7\xcd\xe4\xb0", 755224],
      ["\x75\xa4\x8a\x19\xd4\xcb\xe1\x00\x64\x4e\x8a\xc1\x39\x7e\xea\x74\x7a\x2d\x33\xab", 287082],
      ["\x0b\xac\xb7\xfa\x08\x2f\xef\x30\x78\x22\x11\x93\x8b\xc1\xc5\xe7\x04\x16\xff\x44", 359152],
      ["\x66\xc2\x82\x27\xd0\x3a\x2d\x55\x29\x26\x2f\xf0\x16\xa1\xe6\xef\x76\x55\x7e\xce", 969429],
      ["\xa9\x04\xc9\x00\xa6\x4b\x35\x90\x98\x74\xb3\x3e\x61\xc5\x93\x8a\x8e\x15\xed\x1c", 338314],
      ["\xa3\x7e\x78\x3d\x7b\x72\x33\xc0\x83\xd4\xf6\x29\x26\xc7\xa2\x5f\x23\x8d\x03\x16", 254676],
      ["\xbc\x9c\xd2\x85\x61\x04\x2c\x83\xf2\x19\x32\x4d\x3c\x60\x72\x56\xc0\x32\x72\xae", 287922],
      ["\xa4\xfb\x96\x0c\x0b\xc0\x6e\x1e\xab\xb8\x04\xe5\xb3\x97\xcd\xc4\xb4\x55\x96\xfa", 162583],
      ["\x1b\x3c\x89\xf6\x5e\x6c\x9e\x88\x30\x12\x05\x28\x23\x44\x3f\x04\x8b\x43\x32\xdb", 399871],
      ["\x16\x37\x40\x98\x09\xa6\x79\xdc\x69\x82\x07\x31\x0c\x8c\x7f\xc0\x72\x90\xd9\xe5", 520489]
    ].each do |(hmac, expected_hotp)|
      actual_hotp = hotp.hotp(hmac, digits = 6)
      assert_equal expected_hotp, actual_hotp
    end
  end

  def test_compare_int_to_bytestring_and_array_pack
    int_to_bytestring = -> (int, padding = 8) do
      result = []
      until int == 0
        result << (int & 0xFF).chr
        int >>=  8
      end
      result.reverse.join.rjust(padding, 0.chr)
    end

    largest_64_bit_unsigned_integer = 2 ** 64
    10.times do
      random_integer = rand(largest_64_bit_unsigned_integer)

      bytestring_from_method = int_to_bytestring.call(random_integer)
      bytestring_from_array_pack = [random_integer].pack('Q>')

      assert_equal bytestring_from_method, bytestring_from_array_pack
    end
  end

end
