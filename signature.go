package gosigner

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"sort"
	"time"
)

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version                    int
	DigestAlgorithmIdentifiers asn1.RawValue `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos                asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           algorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm algorithmIdentifier
	EncryptedDigest           []byte
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

func nullAlgorithmParameter() asn1.RawValue {
	return asn1.NullRawValue
}

func buildPKCS7Signature(key *rsa.PrivateKey, chain []*x509.Certificate, contentHash []byte, signingTime time.Time) ([]byte, error) {
	if key == nil {
		return nil, errors.New("private key is required")
	}
	if len(chain) == 0 || chain[0] == nil {
		return nil, errors.New("certificate chain must include signer certificate")
	}

	contentTypeAttr, err := newAttribute(oidContentType, oidData)
	if err != nil {
		return nil, err
	}
	messageDigestAttr, err := newAttribute(oidMessageDigest, contentHash)
	if err != nil {
		return nil, err
	}
	signingTimeAttr, err := newAttribute(oidSigningTime, signingTime.UTC())
	if err != nil {
		return nil, err
	}

	authAttrsSetDER, authAttrsSetContent, err := marshalAttributesSet([]attribute{
		contentTypeAttr,
		signingTimeAttr,
		messageDigestAttr,
	})
	if err != nil {
		return nil, err
	}

	authAttrHash := sha256.Sum256(authAttrsSetDER)
	encryptedDigest, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, authAttrHash[:])
	if err != nil {
		return nil, err
	}

	digestAlgorithm := algorithmIdentifier{Algorithm: oidSHA256, Parameters: nullAlgorithmParameter()}
	digestEncryptionAlgorithm := algorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: nullAlgorithmParameter()}

	signer := signerInfo{
		Version: 1,
		IssuerAndSerialNumber: issuerAndSerial{
			IssuerName:   asn1.RawValue{FullBytes: chain[0].RawIssuer},
			SerialNumber: chain[0].SerialNumber,
		},
		DigestAlgorithm: digestAlgorithm,
		AuthenticatedAttributes: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      authAttrsSetContent,
		},
		DigestEncryptionAlgorithm: digestEncryptionAlgorithm,
		EncryptedDigest:           encryptedDigest,
	}

	signerDER, err := asn1.Marshal(signer)
	if err != nil {
		return nil, err
	}
	signerInfos := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: signerDER}

	digestAlgorithmDER, err := asn1.Marshal(digestAlgorithm)
	if err != nil {
		return nil, err
	}
	digestAlgorithms := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: digestAlgorithmDER}

	certBytes := make([]byte, 0)
	for _, cert := range chain {
		if cert == nil {
			continue
		}
		certBytes = append(certBytes, cert.Raw...)
	}
	certificates := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certBytes}

	sd := signedData{
		Version:                    1,
		DigestAlgorithmIdentifiers: digestAlgorithms,
		ContentInfo: contentInfo{
			ContentType: oidData,
		},
		Certificates: certificates,
		SignerInfos:  signerInfos,
	}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}

	outer := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	}

	return asn1.Marshal(outer)
}

func newAttribute(oid asn1.ObjectIdentifier, value any) (attribute, error) {
	valueDER, err := asn1.Marshal(value)
	if err != nil {
		return attribute{}, err
	}

	return attribute{
		Type: oid,
		Values: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      valueDER,
		},
	}, nil
}

func marshalAttributesSet(attrs []attribute) ([]byte, []byte, error) {
	encodedAttrs := make([][]byte, 0, len(attrs))
	for _, attr := range attrs {
		attrDER, err := asn1.Marshal(attr)
		if err != nil {
			return nil, nil, err
		}
		encodedAttrs = append(encodedAttrs, attrDER)
	}

	sort.Slice(encodedAttrs, func(i, j int) bool {
		return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
	})

	setContent := make([]byte, 0)
	for _, attrDER := range encodedAttrs {
		setContent = append(setContent, attrDER...)
	}

	setDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      setContent,
	})
	if err != nil {
		return nil, nil, err
	}

	return setDER, setContent, nil
}
