package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func VerifyOTP(secret, otp string, timeStep, window, digits int) bool {
	if timeStep <= 0 {
		timeStep = 30
	}
	if digits <= 0 {
		digits = 6
	}

	now := time.Now().Unix()
	currentCounter := now / int64(timeStep)

	for i := -window; i <= window; i++ {
		counter := currentCounter + int64(i)
		generated, err := generateOTPForCounter(secret, counter, digits)
		if err != nil {
			return false
		}
		if generated == otp {
			return true
		}
	}

	return false
}

func GenerateOTP(secret string, timeStep, digits int) (string, error) {
	if timeStep <= 0 {
		timeStep = 30
	}
	if digits <= 0 {
		digits = 6
	}

	now := time.Now().Unix()
	counter := now / int64(timeStep)
	return generateOTPForCounter(secret, counter, digits)
}

func generateOTPForCounter(secret string, counter int64, digits int) (string, error) {
	key, err := base32Decode(secret)
	if err != nil {
		return "", err
	}

	var msg [8]byte
	msg[0] = 0
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4] = byte(counter >> 24)
	msg[5] = byte(counter >> 16)
	msg[6] = byte(counter >> 8)
	msg[7] = byte(counter)

	h := hmac.New(sha1.New, key)
	_, _ = h.Write(msg[:])
	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F

	code := (int(hash[offset])&0x7F)<<24 |
		(int(hash[offset+1])&0xFF)<<16 |
		(int(hash[offset+2])&0xFF)<<8 |
		(int(hash[offset+3]) & 0xFF)

	mod := 1
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code = code % mod

	format := "%0" + strconv.Itoa(digits) + "d"
	return fmt.Sprintf(format, code), nil
}

func base32Decode(data string) ([]byte, error) {
	const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	data = strings.ToUpper(data)

	var bitBuffer string
	for _, r := range data {
		idx := strings.IndexRune(base32Chars, r)
		if idx == -1 {
			return nil, errors.New("invalid base32 character")
		}
		bits := strconv.FormatInt(int64(idx), 2)

		for len(bits) < 5 {
			bits = "0" + bits
		}
		bitBuffer += bits
	}

	var result []byte
	for len(bitBuffer) >= 8 {
		byteStr := bitBuffer[:8]
		bitBuffer = bitBuffer[8:]

		val, err := strconv.ParseInt(byteStr, 2, 64)
		if err != nil {
			return nil, err
		}
		result = append(result, byte(val))
	}

	return result, nil
}

func GenerateTwoFactorSecret() string {
	base32Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	secret := make([]byte, 16)

	for i := 0; i < 16; i++ {
		b := make([]byte, 1)
		_, err := rand.Read(b)
		if err != nil {
            return ""
		}

		secret[i] = base32Chars[int(b[0])%32]
	}

    return string(secret)
}

func BuildUrl(secret string, email string, issuer string) string {
	label := url.QueryEscape(fmt.Sprintf("%s:%s", issuer, email))

	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("period", "30")
	v.Set("digits", "6")
	v.Set("algorithm", "SHA1")

	return fmt.Sprintf("otpauth://totp/%s?%s", label, v.Encode())
}

func GenerateRecoveryCodes(count int) []string {
	var recoveryCodes []string

	for i := 0; i <= count; i++ {
		recoveryCodes = append(recoveryCodes, rand.Text())
	}

	return recoveryCodes
}