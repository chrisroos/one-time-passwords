1. Generating OTPs

  * HOTP - https://www.ietf.org/rfc/rfc4226.txt
  * TOTP - https://www.ietf.org/rfc/rfc6238.txt
  * Generate HMAC using secret and counter
  * Take least significant nibble of HMAC and use as offset
  * Take 4 bytes from HMAC starting at offset
  * Generate 31bit integer by ignoring the most significant bit
  * Use the last n (6) digits from the integer as the OTP

  * Use Ruby script to demonstrate this process

2. HOTPs

  * Counter needs to be synchronised between server and client which is problematic.

  * Compare result of using oathtool and otp.rb
    * `ruby otp.rb secret-key 123`
    * `ruby -e "puts 'secret-key'.unpack('H*')" | pbcopy`
    * `oathtool --hotp --counter 123 --verbose `pbpaste`

  * Convert key to hex for oathtool
    * `ruby -e "puts '<key>'.unpack('H*')"`

3. TOTPs

  * Avoids problem of counter synchronisation by relying on seconds since the epoch.

  * Same as HOTP but counter is number of 30 second intervals between the epoch and now.
    * Generate counter: expr `date +%s` / 30
    * Compare with oathtool
      * `oathtool --totp --verbose 7365637265742d6b6579`
    * Compare with oathtool using hotp
      * `oathtool --hotp --counter `<counter-from-totp-run>` --verbose 7365637265742d6b6579`
    * Compare with otp.rb
      * `ruby otp.rb secret-key <counter-from-totp-run>`
