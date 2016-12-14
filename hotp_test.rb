require 'test/unit'
require_relative 'hotp'

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

end

class UsingRfc4226TestValuesTest < Test::Unit::TestCase

  def setup
    @key = '12345678901234567890'
    @hotp = Hotp.new
  end

  def test_should_match_hmac_from_test_data_in_rfc_4226_when_count_is_0
    hmac = @hotp.hmac(@key, counter = 0)
    assert_equal 'cc93cf18508d94934c64b65d8ba7667fb7cde4b0', hmac
  end

  def test_should_match_hmac_from_test_data_in_rfc_4226_when_count_is_1
    hmac = @hotp.hmac(@key, counter = 1)
    assert_equal '75a48a19d4cbe100644e8ac1397eea747a2d33ab', hmac
  end

  def test_should_match_hmac_from_test_data_in_rfc_4226_when_count_is_2
    hmac = @hotp.hmac(@key, counter = 2)
    assert_equal '0bacb7fa082fef30782211938bc1c5e70416ff44', hmac
  end

  def test_should_match_hmac_from_test_data_in_rfc_4226_when_count_is_3
    hmac = @hotp.hmac(@key, counter = 3)
    assert_equal '66c28227d03a2d5529262ff016a1e6ef76557ece', hmac
  end

  def test_should_match_hmac_from_test_data_in_rfc_4226_when_count_is_4
    hmac = @hotp.hmac(@key, counter = 4)
    assert_equal 'a904c900a64b35909874b33e61c5938a8e15ed1c', hmac
  end

  def test_should_match_hmac_from_test_data_in_rfc_4226_when_count_is_5
    hmac = @hotp.hmac(@key, counter = 5)
    assert_equal 'a37e783d7b7233c083d4f62926c7a25f238d0316', hmac
  end

  def test_should_match_hmac_from_test_data_in_rfc_4226_when_count_is_6
    hmac = @hotp.hmac(@key, counter = 6)
    assert_equal 'bc9cd28561042c83f219324d3c607256c03272ae', hmac
  end

  def test_should_match_hmac_from_test_data_in_rfc_4226_when_count_is_7
    hmac = @hotp.hmac(@key, counter = 7)
    assert_equal 'a4fb960c0bc06e1eabb804e5b397cdc4b45596fa', hmac
  end

  def test_should_match_hmac_from_test_data_in_rfc_4226_when_count_is_8
    hmac = @hotp.hmac(@key, counter = 8)
    assert_equal '1b3c89f65e6c9e883012052823443f048b4332db', hmac
  end

  def test_should_match_hmac_from_test_data_in_rfc_4226_when_count_is_9
    hmac = @hotp.hmac(@key, counter = 9)
    assert_equal '1637409809a679dc698207310c8c7fc07290d9e5', hmac
  end

  def test_should_match_hotp_from_test_data_in_rfc_4226_when_using_hmac_for_count_0
    hmac = "\xcc\x93\xcf\x18\x50\x8d\x94\x93\x4c\x64\xb6\x5d\x8b\xa7\x66\x7f\xb7\xcd\xe4\xb0"
    expected_hotp = 755224
    actual_hotp = @hotp.hotp(hmac, digits = 6)
    assert_equal expected_hotp, actual_hotp
  end

  def test_should_match_hotp_from_test_data_in_rfc_4226_when_using_hmac_for_count_1
    hmac = "\x75\xa4\x8a\x19\xd4\xcb\xe1\x00\x64\x4e\x8a\xc1\x39\x7e\xea\x74\x7a\x2d\x33\xab"
    expected_hotp = 287082
    actual_hotp = @hotp.hotp(hmac, digits = 6)
    assert_equal expected_hotp, actual_hotp
  end

  def test_should_match_hotp_from_test_data_in_rfc_4226_when_using_hmac_for_count_2
    hmac = "\x0b\xac\xb7\xfa\x08\x2f\xef\x30\x78\x22\x11\x93\x8b\xc1\xc5\xe7\x04\x16\xff\x44"
    expected_hotp = 359152
    actual_hotp = @hotp.hotp(hmac, digits = 6)
    assert_equal expected_hotp, actual_hotp
  end

  def test_should_match_hotp_from_test_data_in_rfc_4226_when_using_hmac_for_count_3
    hmac = "\x66\xc2\x82\x27\xd0\x3a\x2d\x55\x29\x26\x2f\xf0\x16\xa1\xe6\xef\x76\x55\x7e\xce"
    expected_hotp = 969429
    actual_hotp = @hotp.hotp(hmac, digits = 6)
    assert_equal expected_hotp, actual_hotp
  end

  def test_should_match_hotp_from_test_data_in_rfc_4226_when_using_hmac_for_count_4
    hmac = "\xa9\x04\xc9\x00\xa6\x4b\x35\x90\x98\x74\xb3\x3e\x61\xc5\x93\x8a\x8e\x15\xed\x1c"
    expected_hotp = 338314
    actual_hotp = @hotp.hotp(hmac, digits = 6)
    assert_equal expected_hotp, actual_hotp
  end

  def test_should_match_hotp_from_test_data_in_rfc_4226_when_using_hmac_for_count_5
    hmac = "\xa3\x7e\x78\x3d\x7b\x72\x33\xc0\x83\xd4\xf6\x29\x26\xc7\xa2\x5f\x23\x8d\x03\x16"
    expected_hotp = 254676
    actual_hotp = @hotp.hotp(hmac, digits = 6)
    assert_equal expected_hotp, actual_hotp
  end

  def test_should_match_hotp_from_test_data_in_rfc_4226_when_using_hmac_for_count_6
    hmac = "\xbc\x9c\xd2\x85\x61\x04\x2c\x83\xf2\x19\x32\x4d\x3c\x60\x72\x56\xc0\x32\x72\xae"
    expected_hotp = 287922
    actual_hotp = @hotp.hotp(hmac, digits = 6)
    assert_equal expected_hotp, actual_hotp
  end

  def test_should_match_hotp_from_test_data_in_rfc_4226_when_using_hmac_for_count_7
    hmac = "\xa4\xfb\x96\x0c\x0b\xc0\x6e\x1e\xab\xb8\x04\xe5\xb3\x97\xcd\xc4\xb4\x55\x96\xfa"
    expected_hotp = 162583
    actual_hotp = @hotp.hotp(hmac, digits = 6)
    assert_equal expected_hotp, actual_hotp
  end

  def test_should_match_hotp_from_test_data_in_rfc_4226_when_using_hmac_for_count_8
    hmac = "\x1b\x3c\x89\xf6\x5e\x6c\x9e\x88\x30\x12\x05\x28\x23\x44\x3f\x04\x8b\x43\x32\xdb"
    expected_hotp = 399871
    actual_hotp = @hotp.hotp(hmac, digits = 6)
    assert_equal expected_hotp, actual_hotp
  end

  def test_should_match_hotp_from_test_data_in_rfc_4226_when_using_hmac_for_count_9
    hmac = "\x16\x37\x40\x98\x09\xa6\x79\xdc\x69\x82\x07\x31\x0c\x8c\x7f\xc0\x72\x90\xd9\xe5"
    expected_hotp = 520489
    actual_hotp = @hotp.hotp(hmac, digits = 6)
    assert_equal expected_hotp, actual_hotp
  end

end

class ArrayPackTest < Test::Unit::TestCase

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
