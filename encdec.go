package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
    //"flag" // command line flags
    "fmt"
    "io/ioutil" // reading/writing files
    //"os" //
    "strings"
    //"time" // timing encryption/decryption
    "unicode"
)

// Sizes are in bytes
// We are going to use AES128 for speed, it should be fine
const kAesKeySize = 16
// Recommended by NIST https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
const kAesNonceSize = 12

// random oracle used in RSA-OAEP
var rndOracle = sha256.New()

var (
    ErrorEncrypt = errors.New("Encryption failed")
    ErrorDecrypt = errors.New("Decryption failed")
    ErrorPemType = errors.New("Unexpected PEM type")
    ErrorDecode = errors.New("RSA key decoding failed")
)


func bzero(arr []byte) {
    for i := range arr {
        arr[i] = 0
    }
}

func generateRandomBytes(size int) ([]byte, error) {
    r := make([]byte, size)
    _, err := rand.Read(r)
    return r, err
}

func decodeKey(key []byte, pemType1 string) ([]byte, error) {
    block, rest := pem.Decode(key)

    if block != nil { // might be PEM
        if block.Type == pemType1 { // correct PEM
            return block.Bytes, nil
        } else { // incorrect PEM
            return nil, ErrorPemType
        }
    } else { // might be DER
        return rest, nil
    }
}

func decodePrivateKey(key []byte) (*rsa.PrivateKey, error) {
    decodedKey, err := decodeKey(key, "RSA PRIVATE KEY")

    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorPemType
    }

    priv, err := x509.ParsePKCS1PrivateKey(decodedKey)

    if err != nil {
        if strings.HasSuffix(err.Error(), "trailing data") {
            priv, err = x509.ParsePKCS1PrivateKey(bytes.TrimRightFunc(decodedKey, unicode.IsSpace))
            if err != nil {
                return nil, ErrorDecode
            }
        } else {
            return nil, ErrorDecode
        }
    }
    return priv, nil
}

func decodePublicKey(key []byte) (*rsa.PublicKey, error) {
    decodedKey, err := decodeKey(key, "RSA PUBLIC KEY")

    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorPemType
    }

    pub, err := x509.ParsePKCS1PublicKey(decodedKey)

    if err != nil {
        if strings.HasSuffix(err.Error(), "trailing data") {
            pub, err = x509.ParsePKCS1PublicKey(bytes.TrimRightFunc(decodedKey, unicode.IsSpace))
            if err != nil {
                return nil, ErrorDecode
            }
        } else {
            return nil, ErrorDecode
        }
    }
    return pub, nil
}

func encrypt(key *[kAesKeySize]byte, plain_data []byte) ([]byte, error) {
    block, err := aes.NewCipher(key[:])
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }

    nonce, err := generateRandomBytes(kAesNonceSize)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }

    encrypted_data := aesgcm.Seal(nil, nonce, plain_data, nil)

    // Prepend the nonce before the encrypted data so we can retrieve it later
    encrypted_data = append(nonce, encrypted_data...)

    return encrypted_data, nil
}

func decrypt(key *[kAesKeySize]byte, encrypted_data []byte) ([]byte, error) {
    block, err := aes.NewCipher(key[:])
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorDecrypt
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorDecrypt
    }

    nonce := make([]byte, kAesNonceSize)
    copy(nonce, encrypted_data[:kAesNonceSize])

    data, err := aesgcm.Open(nil, nonce, encrypted_data[kAesNonceSize:], nil)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorDecrypt
    }

    return data, nil
}

func Seal(pub *rsa.PublicKey, plain_data []byte) ([]byte, error) {
    var key [kAesKeySize]byte
    tmpkey, err := generateRandomBytes(kAesKeySize)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }
    copy(key[:], tmpkey)
    bzero(tmpkey)

    encrypted_data, err := encrypt(&key, plain_data)

    // RSA key has to be at least 656 bits long, given 128 bit AES and 256 bit SHA
    encrypted_key, err := rsa.EncryptOAEP(rndOracle, rand.Reader, pub, key[:], nil)
    bzero(key[:])

    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }

    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }

    // Prepend encrypted data with RSA-encrypted AES key
    encrypted_data = append(encrypted_key, encrypted_data...)
    return encrypted_data, nil
}

func Open(priv *rsa.PrivateKey, encrypted_data []byte) ([]byte, error) {
    var key [kAesKeySize]byte
    // Extract RSA-encrypted AES key from the start of the file
    encrypted_key := make([]byte, priv.PublicKey.Size())
    copy(encrypted_key, encrypted_data[:priv.PublicKey.Size()])

    tmpkey, err := rsa.DecryptOAEP(rndOracle, rand.Reader, priv, encrypted_key, nil)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorDecrypt
    }

    copy(key[:], tmpkey)
    bzero(tmpkey)

    plain_data, err := decrypt(&key, encrypted_data[priv.PublicKey.Size():])
    bzero(key[:])

    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorDecrypt
    }

    return plain_data, nil
}

func EncryptFile(key []byte, in_path string, out_path string) error {
    data, err := ioutil.ReadFile(in_path)
    if err != nil {
        return err
    }

    pub, err := decodePublicKey(key)
    if err != nil {
        return ErrorDecode
    }

    encrypted_data, err := Seal(pub, data)
    if err != nil {
        return err
    }

    return ioutil.WriteFile(out_path, encrypted_data, 0644)
}

func DecryptFile(key []byte, in_path string, out_path string) error {
    encrypted_data, err := ioutil.ReadFile(in_path)
    if err != nil {
        return err
    }

    priv, err := decodePrivateKey(key)
    if err != nil {
        return ErrorDecode
    }
    err = priv.Validate()
    if err != nil {
        return err
    }

    plain_data, err := Open(priv, encrypted_data)
    if err != nil {
        return err
    }

    return ioutil.WriteFile(out_path, plain_data, 0644)
}

/*
func main() {
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Usage: %s [-d|-e] <in_file> <out_file> <key_file>\n", os.Args[0])
    }

    decryptFlag := flag.Bool("d", false, "decrypt <in_file> into <out_file> using <key_file>")
    encryptFlag := flag.Bool("e", false, "encrypt <in_file> into <out_file> using <key_file>")
    flag.Parse()

    if flag.NArg() < 3 {
        flag.Usage()
        return
    }

    start := time.Now()

    key, err := ioutil.ReadFile(flag.Arg(2))
    if err != nil {
        panic(err.Error())
    }

    if *decryptFlag && !*encryptFlag {
        err := DecryptFile(key, flag.Arg(0), flag.Arg(1))
        if err != nil {
            panic(err.Error())
        }
    } else if *encryptFlag && !*decryptFlag {
        err := EncryptFile(key, flag.Arg(0), flag.Arg(1))
        if err != nil {
            panic(err.Error())
        }
    }

    elapsed := time.Since(start)
    fmt.Printf("Took %s\n", elapsed)
}
*/
