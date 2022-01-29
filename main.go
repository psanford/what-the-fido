package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/inconshreveable/log15"
	"github.com/koesie10/webauthn/protocol"
	"github.com/psanford/fido-ident/certinfo"
	"github.com/psanford/lambdahttp/lambdahttpv2"
	"github.com/psanford/logmiddleware"
)

var (
	addr    = flag.String("listen-addr", "127.0.0.1:1234", "Host/Port to listen on")
	cliMode = flag.String("mode", "", "execution mode: http|lambda")

	relyingPartyID   = flag.String("relying-party-id", "what-the-fido.sanford.io", "Webautn relyingPartyID")
	relyingPartyName = flag.String("relying-party-name", "what-the-fido.sanford.io", "Webautn relyingPartyName")
)

func main() {
	flag.Parse()

	logHandler := log15.StreamHandler(os.Stdout, log15.LogfmtFormat())
	log15.Root().SetHandler(logHandler)

	handler := logmiddleware.New(serveMux())

	switch *cliMode {
	case "http":
		fmt.Printf("Listening on %s\n", *addr)
		panic(http.ListenAndServe(*addr, handler))
	default:
		lambda.Start(lambdahttpv2.NewLambdaHandler(handler))
	}
}

func serveMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/webauthn/registration/start", startRegistrationHanler)
	mux.HandleFunc("/webauthn/registration/finish", finishRegistrationHanler)

	return mux
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.Write(indexHTML)
}

func startRegistrationHanler(w http.ResponseWriter, req *http.Request) {
	lgr := logmiddleware.LgrFromContext(req.Context())
	chal, err := protocol.NewChallenge()
	if err != nil {
		panic(err)
	}

	options := &protocol.CredentialCreationOptions{
		PublicKey: protocol.PublicKeyCredentialCreationOptions{

			Challenge: chal,
			RP: protocol.PublicKeyCredentialRpEntity{
				ID: *relyingPartyID,
				PublicKeyCredentialEntity: protocol.PublicKeyCredentialEntity{
					Name: *relyingPartyName,
				},
			},
			PubKeyCredParams: []protocol.PublicKeyCredentialParameters{
				{
					Type:      protocol.PublicKeyCredentialTypePublicKey,
					Algorithm: protocol.ES256,
				},
			},
			Timeout: 30 * 1000,
			User: protocol.PublicKeyCredentialUserEntity{
				ID: randBytes(20),
				PublicKeyCredentialEntity: protocol.PublicKeyCredentialEntity{
					Name: randHex(10),
				},
				DisplayName: randHex(10),
			},
			// Ask for attestation cert
			Attestation: protocol.AttestationConveyancePreferenceDirect,
			AuthenticatorSelection: protocol.AuthenticatorSelectionCriteria{
				UserVerification: protocol.UserVerificationDiscouraged,
			},
		},
	}

	data, err := json.Marshal(options)
	if err != nil {
		lgr.Error("marshal_options_err", "err", err)
		http.Error(w, http.StatusText(500), 500)
		return
	}

	w.Write(data)
}

func finishRegistrationHanler(w http.ResponseWriter, req *http.Request) {
	lgr := logmiddleware.LgrFromContext(req.Context())

	var attestationResponse protocol.AttestationResponse
	d := json.NewDecoder(req.Body)
	if err := d.Decode(&attestationResponse); err != nil {
		lgr.Error("decode_attesttion_response_err", "err", err)
		http.Error(w, http.StatusText(500), 500)
		return
	}

	parsed, err := protocol.ParseAttestationResponse(attestationResponse)
	if err != nil {
		lgr.Error("parse_attestation_response_err", "err", err)
		http.Error(w, http.StatusText(500), 500)
		return
	}

	var certBytes []byte

	if parsed.Response.Attestation.Fmt == "android-safetynet" {
		jwtI := parsed.Response.Attestation.AttStmt["response"]
		if jwtI == nil {
			j, _ := json.Marshal(parsed)
			lgr.Error("no_attestation_cert_found_for_android-safetynet", "err", err, "parsed", string(j))
			http.Error(w, "No attestation cert found", 500)
			return
		}

		jwtTxt := jwtI.([]byte)

		parts := strings.Split(string(jwtTxt), ".")
		jwt, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			lgr.Error("base64_decode_0_err", "err", err, "jwt_txt", string(parts[0]))
			http.Error(w, "attestation decode err", 500)
			return
		}

		var attr jwtAttr
		err = json.Unmarshal(jwt, &attr)
		if err != nil {
			lgr.Error("decode_json_jwt_err", "err", err, "jwt_txt", string(parts[0]))
			http.Error(w, "attestation decode err", 500)
			return
		}

		certBytes, err = base64.StdEncoding.DecodeString(attr.X5c[0])
		if err != nil {
			lgr.Error("base64_decode_1_err", "err", err, "x5c", attr.X5c)
			http.Error(w, "attestation decode err", 500)
			return
		}
	} else {
		if parsed.Response.Attestation.Fmt != "fido-u2f" {
			lgr.Info("unknown_fmt", "fmt", parsed.Response.Attestation.Fmt, "msg", "trying_u2f_anyways")
		}

		certBytesI := parsed.Response.Attestation.AttStmt["x5c"]

		if certBytesI == nil {
			j, _ := json.Marshal(parsed)
			lgr.Error("no_attestation_cert_provided", "err", err, "parsed", string(j))
			http.Error(w, "No attestation cert provided", 500)
			return
		}

		certBytesISlice := certBytesI.([]interface{})

		certBytes = certBytesISlice[0].([]byte)
	}

	var pemOut bytes.Buffer
	err = pem.Encode(&pemOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		lgr.Error("pem_encode_err", "err", err)
		http.Error(w, http.StatusText(500), 500)
		return
	}

	c, err := x509.ParseCertificate(certBytes)
	if err != nil {
		lgr.Error("parse_certificate_err", "err", err)
		http.Error(w, http.StatusText(500), 500)
		return
	}

	exts := make([]ExtInfo, 0)

	for _, ext := range c.Extensions {
		for _, knownOid := range knownOids {
			if ext.Id.Equal(knownOid.OID) {
				extInfo := ExtInfo{
					OID:  ext.Id.String(),
					Name: knownOid.Name,
				}
				if knownOid.valueFunc != nil {
					extInfo.Value = knownOid.valueFunc(ext)
				}
				exts = append(exts, extInfo)
			}
		}
	}

	txt, err := certinfo.CertificateText(c)
	if err != nil {
		log.Fatalf("Get cert text err: %s\n", err)
	}

	resp := RegResponse{
		CertPEM:  pemOut.String(),
		CertInfo: txt,
		Subject:  c.Subject.String(),
		Exts:     exts,
	}

	json.NewEncoder(w).Encode(resp)
}

type RegResponse struct {
	CertPEM  string    `json:"cert_pem"`
	CertInfo string    `json:"cert_info"`
	Subject  string    `json:"subject"`
	Exts     []ExtInfo `json:"extensions"`
}

type ExtInfo struct {
	OID   string `json:"oid"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type OidMatch struct {
	OID       asn1.ObjectIdentifier
	Name      string
	valueFunc func(pkix.Extension) string
}

// see:
// https://developers.yubico.com/PIV/Introduction/Yubico_Attestation_OID.html
// https://github.com/Yubico/developers.yubico.com/blob/master/static/U2F/yubico-metadata.json
var knownOids = []OidMatch{
	{
		OID:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 2},
		Name: "YubiKey U2FID",
		valueFunc: func(e pkix.Extension) string {
			return string(e.Value)
		},
	},
	{
		OID:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 12},
		Name: "YubiKey FIPS",
	},
	{
		OID:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 2, 1, 1},
		Name: "FIDO U2F Authenticator Transports Extension",
	},
	{
		OID:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4},
		Name: "AAGUID",
		valueFunc: func(e pkix.Extension) string {
			guid := e.Value[2:]
			guidHex := fmt.Sprintf("%x", guid)
			yubikeyHW := yubikeyAAGUIDs[guidHex]
			if yubikeyHW == "" {
				yubikeyHW = "unknown hw"
			}
			return fmt.Sprintf("%s (%s)", guidHex, yubikeyHW)
		},
	},
}

// see:
// https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-Hardware-FIDO2-AAGUIDs
// https://github.com/Yubico/developers.yubico.com/blob/master/static/U2F/yubico-metadata.json
var yubikeyAAGUIDs = map[string]string{
	"149a20218ef6413396b881f8d5b7f1f5": "Security Key NFC;fw5.2",
	"2fc0579f811347eab116bb5a8db9202a": "YubiKey 5 NFC|YubiKey 5C NFC;fw5.2, 5.4",
	"6d44ba9bf6ec2e49b9300c8fe920cb73": "Security Key NFC;fw5.1",
	"73bb0cd4e50249b89c6fb59445bf720b": "YubiKey 5(C) (Nano) FIPS;fw5.4",
	"8520342148f943559bc88a53846e5083": "YubiKey 5Ci FIPS;fw5.4",
	"b92c3f9ac0144056887f140a2501163b": "Security Key By Yubico;fw5.2",
	"c1f9a0bc1dd2404ab27f8e29047a43fd": "YubiKey 5(C) NFC FIPS;fw5.4",
	"c5ef55ffad9a4b9fb580adebafe026d0": "YubiKey 5Ci;fw5.2, 5.4",
	"cb69481e8ff7403993ec0a2729a154a8": "YubiKey 5(C|USBA) (Nano);fw5.1",
	"d8522d9f575b486688a9ba99fa02f35b": "YubiKey Bio Series;fw5.5",
	"ee882879721c491397753dfcce97072a": "YubiKey 5(C|USBA) (Nano);fw5.2, 5.4",
	"f8a011f38c0a4d15800617111f9edc7d": "Security Key By Yubico;fw5.1",
	"fa2b99dc9e3942578f924a30d23c4118": "YubiKey 5 NFC;fw5.1",
}

type jwtAttr struct {
	Alg string   `json:"alg"`
	X5c []string `json:"x5c"`
}

func randBytes(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func randHex(size int) string {
	b := randBytes(size)
	return hex.EncodeToString(b)
}
