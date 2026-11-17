; Make by Grok - Nâng cấp AES-256-GCM với random salt, 2026/01/06
#include-once
#include "CryptoNG.au3"  ; Đặt cùng thư mục; Dựa trên CryptoNG UDF by TheXman
; tải UDF CryptoNG.au3 từ đây: https://www.autoitscript.com/forum/files/file/490-cryptong-udf-cryptography-api-next-generation/


If @Compiled=0 And @ScriptName='ATZUDF_Ticrypt.au3' Then ; TEST ZONE
   Local $password = "PassHere"
   Local $original = "Xin chào sếp, đây là tiếng Việt có dấu nè! 😊"
   ConsoleWrite("Original: " & $original & @CRLF & @CRLF)

   Local $encrypted = TiCryptEn($original, $password)
   ConsoleWrite("$encrypted = " & $encrypted & @CRLF & @CRLF)

   ;~ $encrypted='r1Z4ZNhW5ETv/PB4GnZHr32GUWLsQtczBr1f5fSqnaAK/nKxEzLa9znJrezYT86u7YNKu/la2g4ivV0cyIKC62gvIGxY05/D8BLFW/bQcGgKeBs0ngaHp0jb1d6ip1btRF+4S90JZBFti/AMb2VlBLF2JOLGbKIzQ4N/T44nf7qZ0JaflVn2pN3CigrYftRgdsEyqb8='
   Local $decrypted=TiCryptDe($encrypted, $password&1)
   ConsoleWrite("$decrypted = " & $decrypted & @CRLF & @error& @CRLF)
   MsgBox(64, @ScriptName, $decrypted)
EndIf

Func _EscapeUnicode($sText)
    Local $sResult = ""
    For $i = 1 To StringLen($sText)
        Local $sChar = StringMid($sText, $i, 1)
        Local $iCode = AscW($sChar)
        If $iCode > 127 Then
            $sResult &= "\u" & StringFormat("%04X", $iCode)
        Else
            $sResult &= $sChar
        EndIf
    Next
    Return $sResult
EndFunc

Func _UnescapeUnicode($sText)
    Local $sResult = ""
    Local $i = 1
    While $i <= StringLen($sText)
        If StringMid($sText, $i, 2) = "\u" Then
            Local $sHex = StringMid($sText, $i + 2, 4)
            $sResult &= ChrW(Dec($sHex))
            $i += 6
        Else
            $sResult &= StringMid($sText, $i, 1)
            $i += 1
        EndIf
    WEnd
    Return $sResult
EndFunc

Func TiCryptEn($sText, $sPassword)
    $sText&='' ; fix bug when $sText is number
    If $sText = '' Or $sPassword = "" Then Return SetError(1, 0, "")

    ; Escape Unicode trước
    $sText = _EscapeUnicode($sText)

    ; Random salt 16 byte
    Local $bSalt = _CryptoNG_GenerateRandom($CNG_BCRYPT_RNG_ALGORITHM, 16)

    ; Derive key từ password + salt random
    Local $bKey = _CryptoNG_PBKDF2($sPassword, $bSalt, 100000, 256, $CNG_BCRYPT_SHA256_ALGORITHM)

    ; GCM nonce (IV) 12 byte như chuẩn
    Local $bNonce = _CryptoNG_GenerateRandom($CNG_BCRYPT_RNG_ALGORITHM, 12)

    ; Encrypt GCM, auth tag 16 byte
    Local $aResult = _CryptoNG_AES_GCM_EncryptData($sText, $bKey, $bNonce, 16)
    Local $bEncrypted = $aResult[0]
    Local $bAuthTag = $aResult[1]

    ; Ghép: salt + nonce + encrypted + auth tag
    Local $bResult = $bSalt & $bNonce & $bEncrypted & $bAuthTag

    ; Base64 sạch không xuống dòng
    Local $sBase64 = _CryptoNG_CryptBinaryToString($bResult, $CNG_CRYPT_STRING_BASE64)
    $sBase64 = StringReplace($sBase64, @CRLF, '')

;~     ConsoleWrite("Encrypted (Base64 GCM): " & $sBase64 & @CRLF)
    Return $sBase64
EndFunc

Func TiCryptDe($sBase64Encrypted, $sPassword)
    Local $bData = _CryptoNG_CryptStringToBinary($sBase64Encrypted, $CNG_CRYPT_STRING_BASE64)

    If BinaryLen($bData) < 16 + 12 + 16 Then Return SetError(1, 0, "") ; Dữ liệu quá ngắn

    ; Tách phần
    Local $bSalt = BinaryMid($bData, 1, 16)
    Local $bNonce = BinaryMid($bData, 17, 12)
    Local $iEncryptedLen = BinaryLen($bData) - 16 - 12 - 16
    Local $bEncrypted = BinaryMid($bData, 29, $iEncryptedLen)
    Local $bAuthTag = BinaryMid($bData, 29 + $iEncryptedLen, 16)

    ; Derive key từ password + salt
    Local $bKey = _CryptoNG_PBKDF2($sPassword, $bSalt, 100000, 256, $CNG_BCRYPT_SHA256_ALGORITHM)

    ; Decrypt GCM
    Local $bDecrypted = _CryptoNG_AES_GCM_DecryptData($bEncrypted, $bKey, $bNonce, $bAuthTag)
    If @error > 0 Then Return SetError(1, 0, "")

    Local $sPlaintext = BinaryToString($bDecrypted, 4)

    ; Unescape Unicode
    $sPlaintext = _UnescapeUnicode($sPlaintext)


    ;ConsoleWrite("Decrypted: " & $sPlaintext & @CRLF)
    Return $sPlaintext
EndFunc

