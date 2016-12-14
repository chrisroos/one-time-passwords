require 'openssl'

def log(*args)
  p args
end

counter = 7
key = '12345678901234567890'
digits = 6

puts '## Encoding counter as 8 byte binary string'
counter_as_byte_string = [counter].pack('Q>')
log 'counter', counter
log 'counter as byte string', counter_as_byte_string
log 'counter as hex string', counter_as_byte_string.unpack('H*').first
puts ''

puts '## Generating HMAC'
digest = OpenSSL::Digest.new('sha1')
hmac = OpenSSL::HMAC.digest(digest, key, counter_as_byte_string)
log 'hmac', hmac
log 'hmac as hex', hmac.unpack('H*').first
puts ''

puts '## Determining offset from least significant nibble of last byte of HMAC'
last_byte = hmac.bytes.last
# log 'last byte', last_byte
log 'last byte as hex', last_byte.to_s(16)
least_significant_nibble_of_last_byte = last_byte & 0x0f
log 'least significant nibble of last byte', least_significant_nibble_of_last_byte
offset = least_significant_nibble_of_last_byte
log 'offset', offset
puts ''

puts '## Extracting 4 bytes of HMAC starting from offset'
bytes = hmac.bytes[offset..offset + 3]
log 'bytes', bytes
log 'bytes as hex', bytes.pack('C*').unpack('H*')
puts ''

puts '## After masking most significant bit of most significant byte'
bytes[0] = bytes[0] & 0x7f # 0x7f = 0b01111111.to_s(16)
log 'bytes', bytes
log 'bytes as hex', bytes.pack('C*').unpack('H*')
puts ''

puts '## Converting bytes to integer'
bytes_as_integer = bytes.map { |b| b.to_s(2).rjust(8, '0') }.join('').to_i(2)
log 'bytes as integer', bytes_as_integer
puts ''

puts '## Generate OTP with required number of digits'
log 'digits', digits
otp = bytes_as_integer.modulo(10 ** digits)
log 'otp', otp
