require 'openssl'

class Hotp
  def self.hotp(key, counter)
    hotp = new
    hmac = hotp.hmac(key, counter)
    hotp.hotp(hmac, digits = 6)
  end

  # string = 20 byte binary string
  def dynamic_truncation(string)
    p ['string', string]
    p ['string as hex', string.unpack('H*')]

    bytes_in_string = string.bytes.length
    p ['bytes_in_string', bytes_in_string] # RFC says this should be 20 bytes

    unless bytes_in_string == 20
      raise "Incorrect string size. Should be 20 bytes but is #{bytes_in_string}."
    end

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
    p ['offset byte', offset]
    # Let P = String[OffSet]...String[OffSet+3]
    pee_bytes = string.bytes[offset..offset + 3]
    p ['pee_bytes', pee_bytes]
    pee = pee_bytes.pack('CCCC')
    p ['offset range', "#{offset}..#{offset + 3}"]
    p ['pee', pee]
    p ['pee as hex', pee.unpack('H*')]
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
    hmac = OpenSSL::HMAC.digest(digest, key, counter_to_hex(counter))
  end

  def hotp(hmac, digits)
    sbits = dynamic_truncation(hmac)
    p ['sbits', sbits]

    p ['sbits.length', sbits.length]
    unless sbits.length == 31
      raise "Incorrect string size. Should be 31 bits but is #{sbits.length}"
    end

    snum = sbits.to_i(2)
    p ['snum', snum]
    p ['snum as hex', snum.to_s(16)]

    dee = snum.modulo(10 ** digits)
    p ['dee', dee]
    dee
  end

  def counter_to_hex(counter)
    [counter].pack('Q>')
  end
end
