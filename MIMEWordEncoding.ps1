<## 	
	MIME encoded-word syntax (RFC 2047)
	
	Uses a string of ASCII characters indicating both the original character encoding (the "charset") 
	and the content-transfer-encoding used to map the bytes of the charset into ASCII characters.
	
	An encoded-word may not be more than 75 characters long, including charset, encoding, encoded text, 
	and delimiters.

	format: 
	
	=?charset?encoding?encoded_text?=

		charset : may be any character set registered with IANA
		encoding : can be either "Q" for Q-encoding that is similar to the quoted-printable encoding 
			   or "B" for base64 encoding
		encoded_text : the Q or base64  encoded text
##>

# decode base64 encoded strings to text
$base64 = 'base64_encoded_string'	# string must be divisable by 4

[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64))
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($base64))
[Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($base64))


# Convert \x delimited hex to text

$hex_delimited = '\xYY\xZZ\xAA\xBB\xCC'

ConvertFrom-String -Delimiter "\\x" $hex_delimited	# remove the \x delimiter