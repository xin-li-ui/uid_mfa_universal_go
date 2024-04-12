package universal_sdk

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultStateLength = 36
const minimumStateLength = 22
const maximumStateLength = 1024
const defaultJtiLength = 36
const clientIdLength = 20
const clientSecretLength = 40
const expirationTime = 600
const allowedSkew = time.Duration(60) * time.Second
const healthCheckEndpoint = "https://%s/developer/api/v1/public/mfa_oidc/health_check"
const authorizeEndpoint = "https://%s/external/mfa-verify"
const apiHostURIFormat = "https://%s"
const tokenEndpoint = "https://%s/developer/api/v1/public/mfa_oidc/token"
const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// StateCharacters is the set of possible characters used in the random state
const stateCharacters = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
	"1234567890"
const clientIdError = "The UID client id is invalid."
const clientSecretError = "The UID client secret is invalid."
const usernameError = "The username is invalid."
const parameterError = "Did not recieve expected parameters."
const uidCodeError = "Missing authorization code"
const httpUseError = "This client does not allow use of http, please use https"

var stateLengthError = fmt.Sprintf("State must be at least %d characters long and no longer than %d characters", minimumStateLength, maximumStateLength)
var generateStateLengthError = fmt.Sprintf("Length needs to be at least %d", minimumStateLength)

type Client struct {
	clientId     string
	clientSecret string
	apiHost      string
	redirectUri  string

	uidHttpClient httpClient

	baseGwUrl     string
	basePortalUrl string
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Blocks HTTP requests
func refuseHttpConnection(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, fmt.Errorf(httpUseError)
}

// Creates a http.Transport that pins certs to UID and refuses HTTP connections
func newStrictTLSTransport() *http.Transport {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(uidPinnedCert))

	tlsDialer := &tls.Dialer{
		Config: &tls.Config{
			RootCAs: certPool,
		},
	}
	return &http.Transport{
		DialContext:    refuseHttpConnection,
		DialTLSContext: tlsDialer.DialContext,
	}
}

func NewClient(clientId, clientSecret, apiHost, redirectUri string) (*Client, error) {
	if len(clientId) != clientIdLength {
		return nil, fmt.Errorf(clientIdError)
	}
	if len(clientSecret) != clientSecretLength {
		return nil, fmt.Errorf(clientSecretError)
	}

	c := &Client{
		clientId:     clientId,
		clientSecret: clientSecret,
		apiHost:      apiHost,
		redirectUri:  redirectUri,
		uidHttpClient: &http.Client{
			Transport: newStrictTLSTransport(),
		},
	}
	if strings.Contains(apiHost, "api-gw") {
		c.baseGwUrl = apiHost
	} else {
		c.baseGwUrl = apiHost + "/gw"
	}
	c.basePortalUrl = strings.ReplaceAll(apiHost, "api-gw", "portal")
	return c, nil
}

// Return a cryptographically-secure string of random characters
// with the default length
func (client *Client) GenerateState() (string, error) {
	return client.GenerateStateWithLength(defaultStateLength)
}

// Return a cryptographically-secure string of random characters
// suitable for use in state values.
// length is the number of characters in the randomly generated string
func (client *Client) GenerateStateWithLength(length int) (string, error) {
	if length < minimumStateLength {
		return "", fmt.Errorf(generateStateLengthError)
	}

	result := make([]byte, length)
	possibleCharacters := int64(len(stateCharacters))
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(possibleCharacters))
		if err != nil {
			return "", err
		}
		result[i] = stateCharacters[n.Int64()]
	}
	return string(result), nil
}

// Makes HTTP request to UID
func (client *Client) _makeHttpRequest(url string, params url.Values) ([]byte, error) {
	r, err := http.NewRequest(http.MethodPost, url, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.uidHttpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (client *Client) HealthCheck(username, action, ip, ua string) (*HealthCheckResponse, error) {

	// jwt
	healthCheckUrl := fmt.Sprintf(healthCheckEndpoint, client.baseGwUrl)
	token, err := client.generateHealthCheckClientAssertion(healthCheckUrl, username, action, ip, ua)
	if err != nil {
		return nil, err
	}

	// request
	postParams := url.Values{}
	postParams.Add("client_assertion", token)
	postParams.Add("client_id", client.clientId)
	body, err := client._makeHttpRequest(healthCheckUrl, postParams)
	if err != nil {
		return nil, err
	}

	// response
	responseMessage := &ResponseMessage{}
	err = json.Unmarshal(body, responseMessage)
	if err != nil {
		return nil, err
	}

	dataByte, err := json.Marshal(responseMessage.Data)
	if err != nil {
		return nil, err
	}
	healthCheckResponse := &HealthCheckResponse{}
	err = json.Unmarshal(dataByte, healthCheckResponse)
	if err != nil {
		return nil, err
	}

	if healthCheckResponse.Stat != "OK" {
		return nil, fmt.Errorf("%s: %s", healthCheckResponse.Message, healthCheckResponse.MessageDetail)
	}

	return healthCheckResponse, nil
}

func (client *Client) CreateAuthURL(username, state, action, ip, ua string) (string, error) {

	stateLength := len(state)
	if stateLength < minimumStateLength || stateLength > maximumStateLength {
		return "", fmt.Errorf(stateLengthError)
	}
	if username == "" {
		return "", fmt.Errorf(usernameError)
	}

	requestJWTSigned, err := client.generateRequestJWTSigned(username, action, state, ip, ua)
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Add("scope", "openid")
	params.Add("response_type", "code")
	params.Add("state", state)
	params.Add("client_id", client.clientId)
	params.Add("redirect_uri", client.redirectUri)
	params.Add("request", requestJWTSigned)

	authorizeEndpoint := fmt.Sprintf(authorizeEndpoint, client.basePortalUrl)
	base, err := url.Parse(authorizeEndpoint)
	if err != nil {
		return "", err
	}
	base.RawQuery = params.Encode()
	authorizationURI := base.String()

	return authorizationURI, nil
}

func (client *Client) GetTokenResponse(code string, username string) (*TokenResponse, error) {

	if code == "" {
		return nil, fmt.Errorf(uidCodeError)
	}
	tokenUrl := fmt.Sprintf(tokenEndpoint, client.baseGwUrl)

	jwtToken, err := client.generateTokenClientAssertion(tokenUrl)
	if err != nil {
		return nil, err
	}

	postParams := url.Values{}
	postParams.Add("grant_type", "authorization_code")
	postParams.Add("code", code)
	postParams.Add("client_id", client.clientId)
	postParams.Add("redirect_uri", client.redirectUri)
	postParams.Add("client_assertion_type", clientAssertionType)
	postParams.Add("client_assertion", jwtToken)

	body, err := client._makeHttpRequest(tokenUrl, postParams)
	if err != nil {
		return nil, err
	}
	responseMessage := &ResponseMessage{}
	err = json.Unmarshal(body, responseMessage)
	if err != nil {
		return nil, err
	}

	dataByte, err := json.Marshal(responseMessage.Data)
	if err != nil {
		return nil, err
	}
	bodyToken := &BodyToken{}
	err = json.Unmarshal(dataByte, bodyToken)
	if err != nil {
		return nil, err
	}

	if bodyToken.AccessToken == "" ||
		bodyToken.IdToken == "" ||
		bodyToken.ExpiresIn == 0 ||
		bodyToken.TokenType == "" {
		return nil, fmt.Errorf(parameterError)
	}

	claimsToVerify := MapClaims{
		"aud": client.clientId,
		"iss": fmt.Sprintf(apiHostURIFormat, client.baseGwUrl),
	}

	jwtResponse, err := validateAndDecodeIdToken(bodyToken.IdToken, client.clientSecret, claimsToVerify)

	if err != nil {
		return nil, err
	}

	return jwtResponse, nil
}

func (client *Client) generateHealthCheckClientAssertion(aud, email, action, ip, ua string) (string, error) {
	jti, err := client.GenerateStateWithLength(defaultJtiLength)
	if err != nil {
		return "", err
	}

	claims := MapClaims{
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Second * time.Duration(expirationTime)).Unix(),
		"iss":    client.clientId,
		"sub":    client.clientId,
		"aud":    aud,
		"jti":    jti,
		"ip":     ip,
		"ua":     ua,
		"email":  email,
		"action": action,
	}

	token, err := client.createSignedToken(claims)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (client *Client) generateRequestJWTSigned(email, action, state, ip, ua string) (string, error) {
	jti, err := client.GenerateStateWithLength(defaultJtiLength)
	if err != nil {
		return "", err
	}

	claims := MapClaims{
		"jti":           jti,
		"iat":           time.Now().Unix(),
		"exp":           time.Now().Add(time.Second * time.Duration(expirationTime)).Unix(),
		"scope":         "openid",
		"response_type": "code",
		"client_id":     client.clientId,
		"redirect_uri":  client.redirectUri,
		"state":         state,
		"ip":            ip,
		"ua":            ua,
		"email":         email,
		"action":        action,
	}

	token, err := client.createSignedToken(claims)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (client *Client) generateTokenClientAssertion(aud string) (string, error) {
	jti, err := client.GenerateStateWithLength(defaultJtiLength)
	if err != nil {
		return "", err
	}

	claims := MapClaims{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Second * time.Duration(expirationTime)).Unix(),
		"iss": client.clientId,
		"sub": client.clientId,
		"aud": aud,
		"jti": jti,
	}
	token, err := client.createSignedToken(claims)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (client *Client) createSignedToken(claims MapClaims) (string, error) {
	return jwtCreateSignedToken(claims, client.clientSecret)
}
