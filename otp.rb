require 'openssl'

def puts_usage_message_and_exit
  puts "Usage: #{__FILE__} <key> <counter> [digits]"
  exit 1
end

# Handle arguments
unless key = ARGV.shift
  puts_usage_message_and_exit
end

unless counter = ARGV.shift
  puts_usage_message_and_exit
end
counter = Integer(counter)

digits = Integer(ARGV.shift) rescue 6

# Generate OTP
counter_as_byte_string = [counter].pack('Q>')

digest = OpenSSL::Digest.new('sha1')
hmac = OpenSSL::HMAC.digest(digest, key, counter_as_byte_string)

offset = hmac.bytes.last & 0x0f

bytes = hmac.bytes[offset..offset + 3]
bytes[0] = bytes[0] & 0x7f
bytes_as_integer = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]

puts bytes_as_integer.modulo(10 ** digits)
