# One-time passwords

Exploring HOTP and TOTP in Ruby

## Notes

* [Initiative for Open Authentication](https://openauthentication.org/)
* [1Password blog post about addition of TOTP](https://blog.agilebits.com/2015/01/26/totp-for-1password-users/)
  * Explains why it's not 2FA.
* HOTP
  * HMAC based one-time password
  * [RFC 4226 - HOTP](https://www.ietf.org/rfc/rfc4226.txt)
  * [HOTP on Wikipedia](https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm)
* TOTP
  * Time based one-time password
  * [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238)
  * [TOTP on Wikipedia](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
* Apps
  * Authy
    * Only supports TOTP.
  * 1Password
    * Appears to only support TOTP.
  * Google Authenticator
    * Supports HOTP (counter) and TOTP (time).

## OATH Tool

Using OATH Tool to generate the same token as Authy when using the the same <shared-secret>:

```
$ oathtool --base32 --totp <shared-secret>
```

I tested the above command with the shared secret from our GFR GitHub admin user and confirmed that the tokens were the same in both Authy and on the command line.
