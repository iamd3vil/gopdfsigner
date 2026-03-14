package gopdfsigner

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

// ASN.1 Object Identifiers used in the CMS/PKCS#7 SignedData structure.
// These are defined in RFC 5652 (CMS) and RFC 8017 (PKCS#1).
var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}     // id-data (content type for arbitrary data)
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}     // id-signedData (top-level wrapper)
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1} // SHA-256 digest algorithm
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}     // RSA encryption (signature algorithm)
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}     // authenticated attr: content type
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}     // authenticated attr: message digest
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}     // authenticated attr: signing time
)

// Pre-computed DER encodings for constant CMS structures. These are computed once
// at package init and reused on every signing call to avoid repeated ASN.1 marshaling.
var (
	precomputedContentTypeAttr attribute
	precomputedDigestAlgDER    []byte
	precomputedDigestAlgID     algorithmIdentifier
	precomputedDigestEncAlgID  algorithmIdentifier
)

func init() {
	var err error
	precomputedContentTypeAttr, err = newAttribute(oidContentType, oidData)
	if err != nil {
		panic("gopdfsigner: failed to pre-compute contentType attribute: " + err.Error())
	}

	precomputedDigestAlgID = algorithmIdentifier{Algorithm: oidSHA256, Parameters: nullAlgorithmParameter()}
	precomputedDigestEncAlgID = algorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: nullAlgorithmParameter()}

	precomputedDigestAlgDER, err = asn1.Marshal(precomputedDigestAlgID)
	if err != nil {
		panic("gopdfsigner: failed to pre-compute digestAlgorithm DER: " + err.Error())
	}
}

// The following types mirror the ASN.1 structures defined in RFC 5652 (CMS).
// We use asn1.RawValue for SET fields because Go's encoding/asn1 doesn't
// natively produce DER-sorted SETs — we handle sorting ourselves.

// contentInfo is the top-level CMS wrapper (ContentInfo ::= SEQUENCE).
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData is the CMS SignedData structure (SignedData ::= SEQUENCE).
// For PDF detached signatures, ContentInfo.Content is omitted (the PDF bytes
// are the "content" and are referenced externally via ByteRange).
type signedData struct {
	Version                    int
	DigestAlgorithmIdentifiers asn1.RawValue `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos                asn1.RawValue `asn1:"set"`
}

// signerInfo identifies the signer and carries the encrypted digest.
type signerInfo struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           algorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"` // context-tagged [0] IMPLICIT
	DigestEncryptionAlgorithm algorithmIdentifier
	EncryptedDigest           []byte
}

// issuerAndSerial uniquely identifies the signer's certificate by its
// issuer distinguished name and serial number.
type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// algorithmIdentifier pairs an OID with optional parameters (usually NULL for
// SHA-256 and RSA).
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// attribute represents a single authenticated attribute (type + set of values).
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// nullAlgorithmParameter returns an ASN.1 NULL value, required by SHA-256 and RSA
// algorithm identifiers per RFC 4055 Section 2.1.
func nullAlgorithmParameter() asn1.RawValue {
	return asn1.NullRawValue
}

// buildPKCS7Signature creates a DER-encoded CMS SignedData structure suitable for
// embedding in a PDF /Contents field. It produces a detached signature: the actual
// PDF content is not included in the CMS structure — only its SHA-256 digest
// (passed as contentHash) is referenced via the authenticated attributes.
//
// The signing flow follows RFC 5652 Section 5.4:
//  1. Build authenticated attributes (content type, message digest, signing time)
//  2. DER-encode the attributes as a SET (sorted by encoded bytes)
//  3. Hash the encoded attribute SET with SHA-256
//  4. RSA-sign that hash with PKCS#1 v1.5
//  5. Assemble the SignedData structure with certificate chain and signer info
func buildPKCS7Signature(key *rsa.PrivateKey, chain []*x509.Certificate, certBytesDER []byte, contentHash []byte, signingTime time.Time) ([]byte, error) {
	if key == nil {
		return nil, errors.New("private key is required")
	}
	if len(chain) == 0 || chain[0] == nil {
		return nil, errors.New("certificate chain must include signer certificate")
	}

	// Build the three required authenticated attributes for PDF signatures:
	//   - ContentType: pre-computed (always id-data)
	//   - MessageDigest: the SHA-256 hash of the signed PDF byte ranges
	//   - SigningTime: UTC timestamp of when the signature was created
	messageDigestAttr, err := newAttribute(oidMessageDigest, contentHash)
	if err != nil {
		return nil, err
	}
	signingTimeAttr, err := newAttribute(oidSigningTime, signingTime.UTC())
	if err != nil {
		return nil, err
	}

	// Marshal attributes into a DER-encoded SET. Per DER rules, SET elements
	// must be sorted by their encoded representation. marshalAttributesSet returns
	// both the full SET wrapper (for hashing) and the inner content bytes (for
	// embedding in SignerInfo with a context-specific tag).
	authAttrsSetDER, authAttrsSetContent, err := marshalAttributesSet([]attribute{
		precomputedContentTypeAttr,
		signingTimeAttr,
		messageDigestAttr,
	})
	if err != nil {
		return nil, err
	}

	// Per RFC 5652 Section 5.4: the signature is computed over the DER-encoded
	// authenticated attributes (using the EXPLICIT SET OF tag, not the
	// context-specific [0] tag used in the final SignerInfo).
	authAttrHash := sha256.Sum256(authAttrsSetDER)
	encryptedDigest, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, authAttrHash[:])
	if err != nil {
		return nil, err
	}

	// Build the SignerInfo structure. The authenticated attributes are re-tagged
	// with IMPLICIT [0] (context-specific) for embedding, but the hash was computed
	// over the EXPLICIT SET OF encoding above — this distinction matters.
	si := signerInfo{
		Version: 1,
		IssuerAndSerialNumber: issuerAndSerial{
			IssuerName:   asn1.RawValue{FullBytes: chain[0].RawIssuer},
			SerialNumber: chain[0].SerialNumber,
		},
		DigestAlgorithm: precomputedDigestAlgID,
		AuthenticatedAttributes: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      authAttrsSetContent,
		},
		DigestEncryptionAlgorithm: precomputedDigestEncAlgID,
		EncryptedDigest:           encryptedDigest,
	}

	signerDER, err := asn1.Marshal(si)
	if err != nil {
		return nil, err
	}
	signerInfos := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: signerDER}

	// Use pre-computed digest algorithm DER.
	digestAlgorithms := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: precomputedDigestAlgDER}

	// Use pre-computed DER-encoded certificate chain bytes (passed from Signer).
	certificates := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certBytesDER}

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

	// Wrap in the top-level ContentInfo with id-signedData OID.
	// This is the final DER blob that gets hex-encoded into the PDF /Contents field.
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

// newAttribute creates a CMS attribute with the given OID and a single value
// encoded as a DER SET containing one element.
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

// marshalAttributesSet encodes a slice of attributes into a DER SET OF.
// It returns two byte slices:
//   - setDER: the complete SET wrapper (tag + length + content) — used for hashing
//   - setContent: just the concatenated inner bytes — used for the IMPLICIT [0] tag
//     in SignerInfo (which replaces the SET OF tag with context-specific [0])
//
// Attributes are sorted by their DER encoding per X.690 Section 11.6 (DER SET OF
// requires elements to be sorted by encoded value).
func marshalAttributesSet(attrs []attribute) ([]byte, []byte, error) {
	encodedAttrs := make([][]byte, 0, len(attrs))
	for _, attr := range attrs {
		attrDER, err := asn1.Marshal(attr)
		if err != nil {
			return nil, nil, err
		}
		encodedAttrs = append(encodedAttrs, attrDER)
	}

	// DER requires SET OF elements sorted by encoded byte value.
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
