; Make by Grok - Nâng cấp AES-256-GCM với random salt, 2026/01/06
#include-once
#include "CryptoNG.au3"  ; Đặt cùng thư mục; Dựa trên CryptoNG UDF by TheXman
; tải UDF CryptoNG.au3 từ đây: https://www.autoitscript.com/forum/files/file/490-cryptong-udf-cryptography-api-next-generation/


If @Compiled=0 And @ScriptName='ATZUDF_Ticrypt.au3' Then ; TEST ZONE
   Local $password = "PassHere"
   Local $original = "Xin chào sếp, đây là tiếng Việt có dấu nè! 😊"
   $original= 'Xin chào bạn! 😊 C:\user\ C:\User\'
   ConsoleWrite("Original: " & $original & @CRLF & @CRLF)

   Local $encrypted = TiCryptEn($original, $password)
   ConsoleWrite("$encrypted = " & $encrypted & @CRLF & @CRLF)

;~    $encrypted='r1Z4ZNhW5ETv/PB4GnZHr32GUWLsQtczBr1f5fSqnaAK/nKxEzLa9znJrezYT86u7YNKu/la2g4ivV0cyIKC62gvIGxY05/D8BLFW/bQcGgKeBs0ngaHp0jb1d6ip1btRF+4S90JZBFti/AMb2VlBLF2JOLGbKIzQ4N/T44nf7qZ0JaflVn2pN3CigrYftRgdsEyqb8='
;~    $encrypted='zyERsOAF5b8HElipUAjkDatbDIhOXmBX8XTAt9xw8Qk7T2LkCzy59rvBa76TuHheDZZk7VtIZcouE3zk+2lUu6L44ApRdNfj2cfj6hLFkjjFuQ8='
   Local $decrypted=TiCryptDe($encrypted, $password)
   ConsoleWrite("$decrypted = " & $decrypted & @CRLF & @error& @CRLF)
   MsgBox(64, @ScriptName, $decrypted)
EndIf

Func TiCryptEn($sText, $sPassword)
    $sText&='' ; fix bug when $sText is number
    If $sText = '' Or $sPassword = "" Then Return SetError(1, 0, "")

    ; Random salt 16 byte
    Local $bSalt = _CryptoNG_GenerateRandom($CNG_BCRYPT_RNG_ALGORITHM, 16)

    ; Derive key từ password + salt random
    Local $bKey = _CryptoNG_PBKDF2($sPassword, $bSalt, 100000, 256, $CNG_BCRYPT_SHA256_ALGORITHM)

    ; GCM nonce (IV) 12 byte như chuẩn
    Local $bNonce = _CryptoNG_GenerateRandom($CNG_BCRYPT_RNG_ALGORITHM, 12)

    ; Encrypt GCM, auth tag 16 byte; CryptoNG tự đổi chuỗi sang UTF-8 (giống TextEncoder bên ticrypt.html)
    Local $aResult = _CryptoNG_AES_GCM_EncryptData($sText, $bKey, $bNonce, 16)
    If @error Or Not IsArray($aResult) Then Return SetError(2, 0, "")
    Local $bEncrypted = $aResult[0]
    Local $bAuthTag = $aResult[1]

    ; Ghép: salt + nonce + encrypted + auth tag
    Local $bResult = $bSalt & $bNonce & $bEncrypted & $bAuthTag

    ; Base64 sạch không xuống dòng
    Local $sBase64 = _CryptoNG_CryptBinaryToString($bResult, $CNG_CRYPT_STRING_BASE64)
    $sBase64 = StringReplace($sBase64, @CRLF, '')

;~     ConsoleWrite("Encrypted (Base64 GCM): " & $sBase64 & @CRLF)
    ; Đệm sẵn cặp chuỗi mã/bản rõ vừa tạo, lần đọc kiểm tra ngay sau đó (SWrite) và các lần SRead sau khỏi giải mã lại (sửa 261119)
    Local $sCacheKey = TiCrypt_CacheKey($sBase64, $sPassword)
    If $sCacheKey <> '' Then TiCrypt_Cache('SET', $sCacheKey, $sText)
    Return $sBase64
EndFunc

Func TiCryptDe($sBase64Encrypted, $sPassword)
    ; Tra bộ đệm RAM trước, trúng thì trả ngay, không chạy PBKDF2 (sửa 261119)
    Local $sCacheKey = TiCrypt_CacheKey($sBase64Encrypted, $sPassword)
    If $sCacheKey <> '' Then
        Local $sCached = TiCrypt_Cache('GET', $sCacheKey)
        If @error = 0 Then Return SetError(0, 0, $sCached)
    EndIf
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

    ; CryptoNG đã trả chuỗi giải từ UTF-8; đổi thêm lần nữa sẽ qua ANSI làm mất dấu, chỉ đổi khi nhận Binary
    Local $sPlaintext = $bDecrypted
    If IsBinary($bDecrypted) Then $sPlaintext = BinaryToString($bDecrypted, 4)


    ;ConsoleWrite("Decrypted: " & $sPlaintext & @CRLF)
    ; Chỉ lưu vào bộ đệm RAM khi giải mã thành công (sửa 261119)
    If $sCacheKey <> '' Then TiCrypt_Cache('SET', $sCacheKey, $sPlaintext)
    Return $sPlaintext
EndFunc

; ===== Bộ đệm RAM cho TiCrypt (sửa 261119) =====
; Mục đích: TiCryptDe mỗi lần chạy PBKDF2 100.000 vòng (khoảng 166 ms CPU), các vòng Realtime/Widget đọc lại setting liên tục
; nên lưu bản đã giải mã vào RAM, chỉ giải mã lại khi chuỗi mã trong ini đổi.
; Khóa đệm là HMAC-SHA256(mật khẩu, chuỗi mã): không lưu mật khẩu gốc, đổi mật khẩu hoặc đổi chuỗi mã thì tự trượt đệm.
; Tắt bộ đệm: khai báo Global $TiCrypt_CacheEnable=False ở bất kỳ đâu (đọc bằng Eval nên không cần khai báo trước).
; Xóa bộ đệm: gọi TiCryptDe_CacheClear() (ví dụ khi đăng xuất hoặc đổi mật khẩu).

; Tạo khóa đệm từ chuỗi mã và mật khẩu, trả '' khi tắt đệm hoặc không tạo được (lúc đó giải mã như cũ)
Func TiCrypt_CacheKey($sBase64Encrypted, $sPassword)
    If IsDeclared('TiCrypt_CacheEnable') And Eval('TiCrypt_CacheEnable') = False Then Return ''
    If $sBase64Encrypted = '' Or $sPassword = '' Then Return ''
    Local $bHash = _CryptoNG_HashData($CNG_BCRYPT_SHA256_ALGORITHM, StringToBinary($sBase64Encrypted, 4), True, StringToBinary($sPassword, 4))
    If @error Or BinaryLen($bHash) = 0 Then Return ''
    Return String($bHash)
EndFunc

; Kho đệm dùng chung, biến Static nên không phụ thuộc thứ tự chạy dòng Global
; $sMode: 'GET' lấy bản rõ | 'SET' ghi bản rõ | 'CLEAR' xóa hết | 'COUNT' đếm số mục
Func TiCrypt_Cache($sMode, $sCacheKey = '', $sPlaintext = '')
    Local Static $oCache = 0
    If $sMode = 'CLEAR' Then
        If IsObj($oCache) Then $oCache.RemoveAll()
        Return 1
    EndIf
    If Not IsObj($oCache) Then
        $oCache = ObjCreate('Scripting.Dictionary')
        If Not IsObj($oCache) Then Return SetError(1, 0, '') ; không tạo được kho thì bỏ qua đệm
    EndIf
    Switch $sMode
        Case 'GET'
            If $sCacheKey = '' Then Return SetError(1, 0, '')
            If Not $oCache.Exists($sCacheKey) Then Return SetError(1, 0, '')
            Return SetError(0, 0, $oCache.Item($sCacheKey))
        Case 'SET'
            If $sCacheKey = '' Then Return SetError(1, 0, 0)
            If $oCache.Count >= 256 Then $oCache.RemoveAll() ; giới hạn 256 mục, vượt thì xóa sạch rồi đệm lại
            $oCache.Item($sCacheKey) = $sPlaintext
            Return 1
        Case 'COUNT'
            Return $oCache.Count
    EndSwitch
    Return SetError(2, 0, '')
EndFunc

; Xóa toàn bộ bộ đệm giải mã trong RAM
Func TiCryptDe_CacheClear()
    Return TiCrypt_Cache('CLEAR')
EndFunc
; ===== Hết bộ đệm RAM cho TiCrypt =====
