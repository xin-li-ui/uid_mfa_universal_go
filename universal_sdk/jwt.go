package universal_sdk

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

// This file encapsulates all calls to the JWT library.
// To swap to a different library, only this file should need to be changed.

type MapClaims map[string]interface{}

const signatureAlgorithm = "HS256"
const audLengthError = "didn't receive exactly 1 aud"

func jwtCreateSignedToken(claims MapClaims, secret string) (string, error) {
	return jwtCreateSignedTokenWithSignature(claims, secret, signatureAlgorithm)
}

func jwtCreateSignedTokenWithSignature(claims MapClaims, secret string, signature string) (string, error) {
	req := jwt.New()

	for key, value := range claims {
		req.Set(key, value)
	}

	requestJWTSignedBytes, err := jwt.Sign(req, jwa.SignatureAlgorithm(signature), []byte(secret))
	if err != nil {
		return "", err
	}

	return string(requestJWTSignedBytes), nil
}

func validateAndDecodeIdToken(inToken string, secret string, claims MapClaims) (*TokenResponse, error) {
	ltoken, err := jwt.ParseString(inToken, jwt.WithVerify(signatureAlgorithm, []byte(secret)))
	if err != nil {
		return nil, err
	}

	validateOptions := []jwt.ValidateOption{}

	validateOptions = append(validateOptions, jwt.WithAcceptableSkew(allowedSkew))
	if str, ok := (claims["aud"]).(string); ok {
		validateOptions = append(validateOptions, jwt.WithAudience(str))
	}
	if str, ok := (claims["iss"]).(string); ok {
		validateOptions = append(validateOptions, jwt.WithIssuer(str))
	}

	err = jwt.Validate(ltoken, validateOptions...)
	if err != nil {
		return nil, err
	}
	// JWX token assumes `aud` is an array of strings. Our token assumes aud is a string.
	// Remove 'aud' from a copy of the token to avoid unmarshalling errors
	aud := ltoken.Audience()
	ltoken.Remove("aud")

	// Convert from the JWX token format to our own token object by taking advantage of json marshalling/unmarshalling
	j, err := json.Marshal(ltoken)
	if err != nil {
		return nil, err
	}
	token := &TokenResponse{}
	err = json.Unmarshal(j, &token)
	if err != nil {
		return nil, err
	}

	// Manually copy back over the aud field
	if len(aud) == 1 {
		token.Audience = aud[0]
	} else {
		return nil, fmt.Errorf(audLengthError)
	}

	return token, nil
}
