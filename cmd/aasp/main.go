// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package main implements a server for attestation agent service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"path"
	"strings"
	"os"
	"os/exec"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"encoding/json"
	"encoding/base64"
	"encoding/pem"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"github.com/container-investigations/aaa/pkg/keyprovider"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
)

type AzureInformation struct {
	// Endpoint of the certificate cache service from which
	// the certificate chain endorsing hardware attestations
	// can be retrieved. This is optinal only when the container
	// will expose attest/maa and key/release APIs.
	CertCache attest.CertCache `json:"certcache,omitempty"`

	// Identifier of the managed identity to be used
	// for authenticating with AKV MHSM. This is optional and
	// useful only when the container group has been assigned
	// more than one managed identity.
	Identity common.Identity `json:"identity,omitempty"`
}

var azure_info AzureInformation
var defaultCertCacheEndpoint = "americas.test.acccache.azure.net"

type DecryptConfig struct {
	Parameters map[string][]string
}

type EncryptConfig struct {
	Parameters map[string][]string
	Dc DecryptConfig
}

type KeyWrapParams struct {
    Ec EncryptConfig `json:"ec,omitempty"`
    Optsdata string `json:"optsdata,omitempty"`
}

type KeyUnwrapParams struct {
    Dc DecryptConfig `json:"dc,omitempty"`
    Annotation string `json:"annotation"`
}

type AnnotationPacket struct {
    Kid string `json:"kid"`
    WrappedData []byte `json:"wrapped_data"`
    Iv []byte `json:"iv,omitempty"`
    WrapType string `json:"wrap_type,omitempty"`
    KmsEndpoint string `json:"kms_endpoint,omitempty"`
    AttesterEndpoint string `json:"attester_endpoint,omitempty"`
}

type RSAKeyInfo struct {
    PublicKeyPath string `json:"public_key_path"`
    KmsEndpoint string `json:"kms_endpoint"`
    AttesterEndpoint string `json:"attester_endpoint"`
}

type keyProviderInput struct {
    // Operation is either "keywrap" or "keyunwrap"
    // attestation-agent can only handle the case of "keyunwrap"
    Op string `json:"op"`
    // For attestation-agent, keywrapparams should be empty.
    KeyWrapParams KeyWrapParams `json:"keywrapparams,omitempty"`
    KeyUnwrapParams KeyUnwrapParams `json:"keyunwrapparams,omitempty"`
}

type KeyUnwrapResults struct {
	OptsData []byte `json:"optsdata"`
}

type KeyWrapResults struct {
	Annotation []byte `json:"annotation"`
}

type KeyProviderProtocolOutput struct {
	// KeyWrapResult encodes the results to key wrap if operation is to wrap
	KeyWrapResults KeyWrapResults `json:"keywrapresults,omitempty"`
	// KeyUnwrapResult encodes the result to key unwrap if operation is to unwrap
	KeyUnwrapResults KeyUnwrapResults `json:"keyunwrapresults,omitempty"`
}

// server is used to implement helloworld.GreeterServer.
type server struct {
	keyprovider.UnimplementedKeyProviderServiceServer
}

func (s *server) SayHello(ctx context.Context, in *keyprovider.HelloRequest) (*keyprovider.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &keyprovider.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func directWrap(optsdata []byte, key_path string) ([]byte, error) {
	_, kid := path.Split(key_path)
	var annotation AnnotationPacket
	annotation.Kid = kid
	annotation.Iv = []byte("")
	annotation.WrapType = "rsa_3072"

	var keyInfo RSAKeyInfo
	path := key_path + "-info.json"
	keyInfoBytes, e := os.ReadFile(path)
	if e != nil {
		return nil, fmt.Errorf("Failed to read key info file %v", path)
	}

	err := json.Unmarshal(keyInfoBytes, &keyInfo)
	if err != nil {
		return nil, fmt.Errorf("Invalid RSA key info file %v", path)
	}
	log.Printf("%v", keyInfo)

	annotation.AttesterEndpoint = keyInfo.AttesterEndpoint
	annotation.KmsEndpoint = keyInfo.KmsEndpoint

	pubpem, err := os.ReadFile(keyInfo.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read public key file %v", keyInfo.PublicKeyPath)
	}
	block, _ := pem.Decode([]byte(pubpem))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Invalid public key in %v, error: %v", path, err)
	}

	var ciphertext []byte
	if pubkey, ok := key.(*rsa.PublicKey); ok {
		ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, optsdata, nil)
		if err != nil {
			return nil, fmt.Errorf("Failed to encrypt with the public key %v", err)
		}
	} else {
		return nil, fmt.Errorf("Invalid public RSA key in %v", path)
	}

	annotation.WrappedData = ciphertext
	annotationBytes, _ :=  json.Marshal(annotation)
	return annotationBytes, nil
}

func (s *server) WrapKey(c context.Context, grpcInput *keyprovider.KeyProviderKeyWrapProtocolInput) (*keyprovider.KeyProviderKeyWrapProtocolOutput, error) {
	var input keyProviderInput
	str := string(grpcInput.KeyProviderKeyWrapProtocolInput)
	err := json.Unmarshal(grpcInput.KeyProviderKeyWrapProtocolInput, &input)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Ill-formed key provider input: %v. Error: %v", str, err.Error())
	}
	log.Printf("Key provider input: %v", input)

	var ec = input.KeyWrapParams.Ec
	if len(ec.Parameters["attestation-agent"]) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "attestation-agent must be specified in the encryption config parameters: %v", ec)
	}
	aaKid, _ := base64.StdEncoding.DecodeString(ec.Parameters["attestation-agent"][0])
	tokens := strings.Split(string(aaKid), ":")

	if len(tokens) < 2 {
		return nil, status.Errorf(codes.InvalidArgument, "Key id is not provided in the request")
	}

	aa := tokens[0]
	kid := tokens[1]
	if aa != "aasp" && aa != "aaa" {
		return nil, status.Errorf(codes.InvalidArgument, "Unexpected attestation agent %v specified. Perhaps you send the request to a wrong endpoint?", aa)
	}
	log.Printf("Attestation agent: %v, kid: %v", aa, kid)

	optsdata, err := base64.StdEncoding.DecodeString(input.KeyWrapParams.Optsdata)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument , "Optsdata is not base64 encoding: %v", err)
	}

	annotationBytes, e := directWrap(optsdata, kid)
	if e != nil {
		return nil, status.Errorf(codes.Internal, "%v", e)
	}

	protocolBytes, _ := json.Marshal(KeyProviderProtocolOutput{
		KeyWrapResults: KeyWrapResults{Annotation: annotationBytes},
	})

	return &keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolBytes,
	}, nil
}

func (s *server) UnWrapKey(c context.Context, grpcInput *keyprovider.KeyProviderKeyWrapProtocolInput) (*keyprovider.KeyProviderKeyWrapProtocolOutput, error) {
	var input keyProviderInput
	str := string(grpcInput.KeyProviderKeyWrapProtocolInput)
	err := json.Unmarshal(grpcInput.KeyProviderKeyWrapProtocolInput, &input)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Ill-formed key provider input: %v. Error: %v", str, err.Error())
	}
	log.Printf("Key provider input: %v", input)

	var dc = input.KeyUnwrapParams.Dc
	if len(dc.Parameters["attestation-agent"]) == 0 {
		return nil, status.Errorf(codes.InvalidArgument , "attestation-agent must be specified in decryption config parameters: %v", str)
	}
	aa, _ := base64.StdEncoding.DecodeString(dc.Parameters["attestation-agent"][0])
	log.Printf("Attestation agent name: %v", string(aa))

	if string(aa) != "aasp" && string(aa) != "aaa" {
		return nil, status.Errorf(codes.InvalidArgument, "Unexpected attestation agent %v specified. Perhaps you send the request to a wrong endpoint?", string(aa))
	}

	var annotationBytes []byte
	annotationBytes, err = base64.StdEncoding.DecodeString(input.KeyUnwrapParams.Annotation)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Annotation is not a base64 encoding: %v. Error: %v", input.KeyUnwrapParams.Annotation, err.Error())
	}
	log.Printf("Decoded annotation: %v", string(annotationBytes))

	var annotation AnnotationPacket
	err = json.Unmarshal(annotationBytes, &annotation)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Ill-formed annotation packet: %v. Error: %v", input.KeyUnwrapParams.Annotation, err.Error())
	}
	log.Printf("Annotation packet: %v", annotation)

	mhsm := skr.MHSM{
		Endpoint:    annotation.KmsEndpoint,
		APIVersion:  "api-version=7.3-preview",
	}

	maa := attest.MAA{
		Endpoint:   annotation.AttesterEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	skrKeyBlob := skr.KeyBlob{
		KID:       annotation.Kid,
		Authority: maa,
		MHSM:      mhsm,
	}

	// MHSM has limit on the request size. We do not pass the EncodedSecurityPolicy here so
	// it is not presented as fine-grained init-time claims in the MAA token, which would
	// introduce larger MAA tokens that MHSM would accept
	keyBytes, err := skr.SecureKeyRelease("", azure_info.CertCache, azure_info.Identity, skrKeyBlob)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "SKR failed: %v", err)
	}

       key, err := x509.ParsePKCS8PrivateKey(keyBytes)
       if err != nil {
                return nil, status.Errorf(codes.Internal, "Released key is invalid: %v", err)
        }

	var out *keyprovider.KeyProviderKeyWrapProtocolOutput = nil
	var plaintext []byte
       if privkey, ok := key.(*rsa.PrivateKey); ok {
               plaintext, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privkey, annotation.WrappedData, nil)
               if err != nil {
                       return nil, status.Errorf(codes.Internal, "Unwrapping failed: %v", err)
               }
       } else {
		return nil, status.Errorf(codes.Internal, "Released key is not a RSA private key: %v", err)
	}

	protocolBytes, _ := json.Marshal(KeyProviderProtocolOutput{
		KeyUnwrapResults: KeyUnwrapResults{OptsData: plaintext},
	})

	return &keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolBytes,
	}, nil

	return out, nil
}

func (s *server) GetReport(c context.Context, in *keyprovider.KeyProviderGetReportInput) (*keyprovider.KeyProviderGetReportOutput, error) {
	reportDataStr := in.GetReportDataHexString()
	log.Printf("Received report data: %v", reportDataStr)

	if _, err := os.Stat("/dev/sev"); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "SEV guest driver is missing: %v", err)
	}

	cmd := exec.Command("/bin/get-snp-report", reportDataStr)
	reportOutput, err := cmd.Output()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate attestation report: %v", err)
	}

	return &keyprovider.KeyProviderGetReportOutput{
		ReportHexString: string(reportOutput),
	}, nil
}

func main() {
	port := flag.String("keyprovider_sock", "127.0.0.1:50000", "Port on which the key provider to listen")
	flag.String("getresource_sock", "127.0.0.1:50001", "Port on which the resource provider to listen. Ignored")
	infile := flag.String("infile", "", "The file with its content to be wrapped")
	key_path := flag.String("keypath", "", "The path to the wrapping key")
	outfile := flag.String("outfile", "", "The file to save the wrapped data")
	flag.Parse()

	if *infile  != "" {
		bytes, err := os.ReadFile(*infile)
		if err != nil {
			log.Fatalf("Can't read input file %v", *infile)
		}
		if *key_path == "" {
			log.Fatalf("The key path is not specified for wrapping")
		}
		if *outfile == "" {
			log.Fatalf("The output file is not specified")
		}

		if _, err := os.Stat(*key_path + "-info.json"); err != nil {
			log.Fatalf("The wrapping key info is not found")
		}

		annotationBytes, e := directWrap(bytes, *key_path)
		if e != nil {
			log.Fatalf("%v", e)
		}

		outstr := base64.StdEncoding.EncodeToString(annotationBytes)
		if err := os.WriteFile(*outfile, []byte(outstr), 0644); err != nil {
			log.Fatalf("Failed to save the wrapped data to %v", *outfile)
		}
		log.Printf("Success! The wrapped data is saved to %v", *outfile)
		return
	}

	lis, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("failed to listen on port %v: %v", *port, err)
	}
	log.Printf("Listening on port %v", *port)

	certCacheEndpoint := os.Getenv("CertCacheEndpoint")
	if  certCacheEndpoint == "" {
		certCacheEndpoint = defaultCertCacheEndpoint
	}

	// Temporary solution until we get the cert chain from the host
	azure_info.CertCache = attest.CertCache{
		AMD: false,
		Endpoint: certCacheEndpoint,
		TEEType: "SevSnpVM",
		APIVersion: "api-version=2020-10-15-preview",
	}
	azure_info.Identity.ClientId = os.Getenv("AZURE_CLIENT_ID")
	if azure_info.Identity.ClientId == "" {
		log.Printf("Warning: Env AZURE_CLIENT_ID is not set")
	}

	s := grpc.NewServer()
	keyprovider.RegisterKeyProviderServiceServer(s, &server{})
	reflection.Register(s)
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start GRPC server: %v", err)
	}
}
