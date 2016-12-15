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
# TODO: Try packing this array using C and then unpacking using V. I think that's what James/Edward suggested at Show & Tell 27
bytes_as_integer = bytes.map { |b| b.to_s(2).rjust(8, '0') }.join('').to_i(2)

puts bytes_as_integer.modulo(10 ** digits)
