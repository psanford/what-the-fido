package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestYubikey(t *testing.T) {
	ts := httptest.NewServer(serveMux())

	defer ts.Close()

	yubikeyReq, err := ioutil.ReadFile("testdata/yubikey-req.json")
	if err != nil {
		t.Fatal(err)
	}

	reqBody := bytes.NewBuffer(yubikeyReq)
	resp, err := http.Post(ts.URL+"/webauthn/registration/finish", "application/json", reqBody)
	if err != nil {
		t.Fatal(err)
	}

	var regResp RegResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	if err != nil {
		t.Fatal(err)
	}

	if regResp.CertPEM != yubikeyCert {
		t.Fatalf("expect yubikey cert %s but got %s", yubikeyCert, regResp.CertPEM)
	}

	expectExts := []ExtInfo{
		{
			OID:   "1.3.6.1.4.1.41482.2",
			Name:  "YubiKey U2FID",
			Value: "1.3.6.1.4.1.41482.1.7",
		},
		{
			OID:  "1.3.6.1.4.1.45724.2.1.1",
			Name: "FIDO U2F Authenticator Transports Extension",
		},
		{
			OID:   "1.3.6.1.4.1.45724.1.1.4",
			Name:  "AAGUID",
			Value: "2fc0579f811347eab116bb5a8db9202a (YubiKey 5 NFC|YubiKey 5C NFC;fw5.2, 5.4)",
		},
	}

	if !cmp.Equal(expectExts, regResp.Exts) {
		t.Fatalf(cmp.Diff(expectExts, regResp.Exts))
	}
}

func TestAndroid(t *testing.T) {
	ts := httptest.NewServer(serveMux())

	defer ts.Close()

	androidReq, err := ioutil.ReadFile("testdata/android-req.json")
	if err != nil {
		t.Fatal(err)
	}

	reqBody := bytes.NewBuffer(androidReq)

	resp, err := http.Post(ts.URL+"/webauthn/registration/finish", "application/json", reqBody)
	if err != nil {
		t.Fatal(err)
	}

	var regResp RegResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	if err != nil {
		t.Fatal(err)
	}

	if regResp.CertPEM != androidCert {
		t.Fatalf("expect android cert %s but got %s", androidCert, regResp.CertPEM)
	}

	expectExts := []ExtInfo{}
	if !cmp.Equal(expectExts, regResp.Exts) {
		t.Fatalf(cmp.Diff(expectExts, regResp.Exts))
	}
}

func TestAndroid2(t *testing.T) {
	ts := httptest.NewServer(serveMux())

	defer ts.Close()

	androidReq, err := ioutil.ReadFile("testdata/android-req-2.json")
	if err != nil {
		t.Fatal(err)
	}

	reqBody := bytes.NewBuffer(androidReq)

	resp, err := http.Post(ts.URL+"/webauthn/registration/finish", "application/json", reqBody)
	if err != nil {
		t.Fatal(err)
	}

	var regResp RegResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	if err != nil {
		t.Fatal(err)
	}

	if regResp.CertPEM != androidCert2 {
		t.Fatalf("expect android cert %s but got %s", androidCert2, regResp.CertPEM)
	}

	expectExts := []ExtInfo{}
	if !cmp.Equal(expectExts, regResp.Exts) {
		t.Fatalf(cmp.Diff(expectExts, regResp.Exts))
	}
}

var yubikeyCert = `-----BEGIN CERTIFICATE-----
MIICvjCCAaagAwIBAgIEXdBO4TANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1
YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYG
A1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTU3MzkzMjc2OTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABCNp4As+URnWqbTRh760QYDNrHHqUpiB4+d9HPWBoTtn
MSupMoY1ncNIDYET1l4UFOzm0Q67LR7I3Zo/Av1cgNSjbDBqMCIGCSsGAQQBgsQK
AgQVMS4zLjYuMS40LjEuNDE0ODIuMS43MBMGCysGAQQBguUcAgEBBAQDAgQwMCEG
CysGAQQBguUcAQEEBBIEEC/AV5+BE0fqsRa7Wo25ICowDAYDVR0TAQH/BAIwADAN
BgkqhkiG9w0BAQsFAAOCAQEAh8odJU4o9FIUYSm3h1UhrTGfnukczFJd3ojEJnxz
ZBnDBye7VfzVFJ05VQzu859HI3mRxK5FH4HLo6LnVrKrKh7cPEhECrQgEgbtjIwD
+AAXQkAAZT1eyng572o82o/6Ua9e0/N+BktXV3TwzPGgMQaWGgql41gyiRc+8YBB
bWF+ozozvRT2h+qexpd7YwPVk6FRiLhNyiqhl9qpnraHtrcQyEl++5PMnCUSygNy
KTzS9DH7d8G+qTFZV23bdecAyjS2EcfztFLSs0Au6+jLLvt9R0pjGW28kObE8F9B
BkJtLKZtPaw3W/LyZXOxs3PK+iENM5K3UtbbKPPi2a/AYQ==
-----END CERTIFICATE-----
`

var androidCert = `-----BEGIN CERTIFICATE-----
MIIFXzCCBEegAwIBAgIQBQsU/vasZZYKAAAAASSoBTANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFENDAeFw0yMTExMjIwNzQyMzVaFw0yMjAyMjAw
NzQyMzRaMB0xGzAZBgNVBAMTEmF0dGVzdC5hbmRyb2lkLmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAKEw9yYJjtXEN+eaPBy8jUEUWQGDbzmYa1mX
aE0EMVlJM77NtouzL8fyEZytcnZmr3O1gnyLtyQBoSAV8NLi0xnEWXxuHGken6n9
kLdG15P8vDk0xNmcMKEwGwNqYDTqLP9Be9sWdD1HZM0zE4AEvrhCIVFytsO26Zm2
66lg7bPv2jnj3OHUCMfumkzUXrOxD6SfaDeMH2P3AS0s5Yk/DrfW2NbL9pAtLSpZ
Bj2drOUkNPcSEBJ7ixu3Teqc5Fky2iuzI8zxfoGdSZQ8H+iBBQIHZV4TaS5AUEdd
LusMBKCVJi6v5cDcPPy96vTOcjRqsUqXlW1MKyzvA/1b2TFCKi8CAwEAAaOCAnAw
ggJsMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMB
Af8EAjAAMB0GA1UdDgQWBBRO5GwbCkU73/BgaFzoNLDgNF4yJTAfBgNVHSMEGDAW
gBQl4hgOsleRlCrl1F2GkIPeU7O4kjBtBggrBgEFBQcBAQRhMF8wKgYIKwYBBQUH
MAGGHmh0dHA6Ly9vY3NwLnBraS5nb29nL2d0czFkNGludDAxBggrBgEFBQcwAoYl
aHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzMWQ0LmRlcjAdBgNVHREEFjAU
ghJhdHRlc3QuYW5kcm9pZC5jb20wIQYDVR0gBBowGDAIBgZngQwBAgEwDAYKKwYB
BAHWeQIFAzA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Jscy5wa2kuZ29vZy9n
dHMxZDRpbnQvX0ZQcXFJSGdYNjguY3JsMIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDv
AHYAKXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4QAAAF9Rs+4EAAABAMA
RzBFAiBrGJC6QtSmWZ6/El5PScjJh0vP5X9ISue/V1KHtPBJFwIhAKLC0awtvqpS
jEBttlwGKDuDiHUaSf/P5j1IcS9kcSelAHUAUaOw9f0BeZxWbbg3eI8MpHrMGyfL
956IQpoN/tSLBeUAAAF9Rs+4eAAABAMARjBEAiBvxem+/q6HDlyl5Nz1W2gtOtGu
Lqq51sDBHEHYQsCp8gIgRVeJ7UWuNdGRYUn05YtG2YGocdXNXnqcD1axTGLp2LAw
DQYJKoZIhvcNAQELBQADggEBAKdC6JgOthZS5qyauZnDNvgPlNKW60pHizMPli5G
aYi2fqs9/CEmF3AwzPgdx1Xurq5jqPMsArd8uaCe8Tl3j6B+7iNBT0UdyygtLG9e
DlY6nOpwmCytNtBau0JhKsELgcdIooZdJ4lqdVJQquyaFzh6JK59WslIrBrPEGul
3ND+8mB9muZiHPrJpcipgh867VQFKehgcUcGDd9hIqfbx4smv5CbKJokc6/hX2EB
Qq2wSarDIU2vqjEXr9Kx2gdQjQJ6/QSTTYowcfwj+KEeHFVTYYp1hj8N8s3aj3py
IPlFFbmUNgcDiFCFeaEbP5fyZBbx4gTH0POcAArfvGx3v74=
-----END CERTIFICATE-----
`

var androidCert2 = `-----BEGIN CERTIFICATE-----
MIIFbzCCBFegAwIBAgIRAP4UU7By5wpREFFKwIqks44wDQYJKoZIhvcNAQELBQAw
RjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBM
TEMxEzARBgNVBAMTCkdUUyBDQSAxRDQwHhcNMjIwNTE5MTIwMzI0WhcNMjIwODE3
MTIwMzIzWjAdMRswGQYDVQQDExJhdHRlc3QuYW5kcm9pZC5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgn3Xmw1zq9y3yrAZAxTs1ztTFoXaK7DbJ
sejbWZx+wzkuYa9r4hg25JAGVq7z16CNtsW9XvNpc5HcLovn/oS/kiPsW+hOKhrP
GPGBxK/OQHkKyHUcej50FtNBLOG5V7Vsw8VjxF5COVMCebvwwYJqx6ghGoKdk2cr
ePS2hb+/Jp7SfPeZpZfyPYAbHVzS4W2ZLIj9CgsKOkvKhuXeVyv1+py9l3SWjsmi
qQOvmEs+n+pqxAj+e1DbOUFjzX5Zf3rIYFubua861GwKSwcyVO4WfTd9QwzXYH9H
VMkVWJaQs+nKEIN8//7vnLwBoDsV8c56GfwSgVxyDg5mwowRAwATAgMBAAGjggJ/
MIICezAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0T
AQH/BAIwADAdBgNVHQ4EFgQU4arkLvXyL3etEbDTwBjGX8qHMGUwHwYDVR0jBBgw
FoAUJeIYDrJXkZQq5dRdhpCD3lOzuJIwewYIKwYBBQUHAQEEbzBtMDgGCCsGAQUF
BzABhixodHRwOi8vb2NzcC5wa2kuZ29vZy9zL2d0czFkNGludC9vUldMQTJWOGxk
YzAxBggrBgEFBQcwAoYlaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzMWQ0
LmRlcjAdBgNVHREEFjAUghJhdHRlc3QuYW5kcm9pZC5jb20wIQYDVR0gBBowGDAI
BgZngQwBAgEwDAYKKwYBBAHWeQIFAzA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8v
Y3Jscy5wa2kuZ29vZy9ndHMxZDRpbnQvX0ZQcXFJSGdYNjguY3JsMIIBBAYKKwYB
BAHWeQIEAgSB9QSB8gDwAHYARqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+
bUcAAAGA3Gp6vAAABAMARzBFAiBSj7BNIfmjbvndlwJ5yYE8OkX8SkzelQk5f4RD
WdqxpwIhAPcQi72oNSOHl3lik27iNS+5rmWkY5w5WQFjOJuf5m2sAHYAQcjKsd8i
RkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvYAAAGA3Gp60gAABAMARzBFAiAlnC8C
6ZzjgvTBWzNv5AsrAraE8U1lCb/m2Rgg5JgcDAIhAOB3kTEmnAucyr1xajEn57EP
gcPg0DywXgkXM3d1UdXpMA0GCSqGSIb3DQEBCwUAA4IBAQB41MX1DI+a9AWPNcir
C34LasF2hxldXXI5UD1fcnIlarnzmLsTurIF7m0j3ULvwU2+g5jy+xy6QCORuMFv
KNPd2NVGUvOytj/nYr7Oa9tyAyRR79ZgOooEgRWVrWYzG2/JVXB3itVzBCZyClPA
KXnSXQQsjOJ3HhiLjUHfaYxPYtCOwKGufxhVw/ptzlLB4HQgqIYvT8mJ84mZ8dhA
9BJ6qQHPVuI3CuSR5TLdCICozDAaTsQg4g6H1X3WwA6scmbL/lAv4gInKS8TKwpJ
y9XN3wv3ixtYeZpH3HvVYbtbbfLKJ5YONeoIvbCChGz9fk4GmPLf3kI7Sq3g/V7I
rwO1
-----END CERTIFICATE-----
`
