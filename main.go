package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {

	if _, err := os.Stat("public.pem"); os.IsNotExist(err) {
		createCertificate()
	} else {
		getCertificate()
	}
}

func createCertificate() {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA private key:", err)
		return
	}

	// Save the private key to a file
	privateKeyFile, err := os.Create("private.pem")
	if err != nil {
		fmt.Println("Error creating private key file:", err)
		return
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	err = pem.Encode(privateKeyFile, privateKeyPEM)
	if err != nil {
		fmt.Println("Error encoding private key:", err)
		return
	}

	fmt.Println("Private key saved to private.pem")

	// Save the public key to a file
	publicKeyFile, err := os.Create("public.pem")
	if err != nil {
		fmt.Println("Error creating public key file:", err)
		return
	}
	defer publicKeyFile.Close()

	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Println("Error marshaling public key:", err)
		return
	}

	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	err = pem.Encode(publicKeyFile, publicKeyPEM)
	if err != nil {
		fmt.Println("Error encoding public key:", err)
		return
	}

	fmt.Println("Public key saved to public.pem")
}

func getCertificate() {
	// Membaca kunci privat dari file
	privateKeyFile, err := ioutil.ReadFile("private.pem")
	if err != nil {
		fmt.Println("Error reading private key file:", err)
		return
	}

	privateKeyPEM, _ := pem.Decode(privateKeyFile)
	if privateKeyPEM == nil {
		fmt.Println("Error decoding private key")
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyPEM.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}

	// Membaca kunci publik dari file
	publicKeyFile, err := ioutil.ReadFile("public.pem")
	if err != nil {
		fmt.Println("Error reading public key file:", err)
		return
	}

	publicKeyPEM, _ := pem.Decode(publicKeyFile)
	if publicKeyPEM == nil {
		fmt.Println("Error decoding public key")
		return
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyPEM.Bytes)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return
	}

	// Pesan yang akan dienkripsi
	originalMessage := "Ini adalah pesan rahasia DevNus"

	// Mengenkripsi pesan menggunakan kunci publik
	encryptedMessage, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey.(*rsa.PublicKey), []byte(originalMessage))
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	fmt.Println("Original Message:", originalMessage)
	fmt.Println("Encrypted Message (with public key):", encryptedMessage)

	// Mendekripsi pesan menggunakan kunci privat
	decryptedMessage, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedMessage)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	fmt.Println("Decrypted Message (with private key):", string(decryptedMessage))
	fmt.Println("Author M.Reza Pahlepi || Developer Nusantara")
}
