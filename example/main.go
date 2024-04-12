package main

import (
	"encoding/json"
	"fmt"
	"github.com/xin-li-ui/uid_mfa_universal_go/universal_sdk"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
)

const uidUnavailable = "UID unavailable"

type Session struct {
	state    string
	username string
	failmode string
}

type Config struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	ApiHost      string `json:"apiHost"`
	RedirectUri  string `json:"redirectUri"`
	Failmode     string `json:"failmode"`
}

func main() {
	session := Session{}
	file, err := os.Open("config.json")
	uidConfig := Config{}
	if err != nil {
		log.Fatal("can't open config file: ", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&uidConfig)
	if err != nil {
		log.Fatal("can't decode config JSON: ", err)
	}
	// Step 1: Create a UID client
	uidClient, err := universal_sdk.NewClient(uidConfig.ClientId, uidConfig.ClientSecret, uidConfig.ApiHost, uidConfig.RedirectUri)
	session.failmode = strings.ToUpper(uidConfig.Failmode)
	if err != nil {
		log.Fatal("Error parsing config: ", err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session.login(w, r, uidClient)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		session.login(w, r, uidClient)
	})
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		session.callback(w, r, uidClient)
	})
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Running demo on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (session *Session) login(w http.ResponseWriter, r *http.Request, client *universal_sdk.Client) {
	if r.Method == "GET" {
		// Render the login template
		renderTemplate("login.html", "This is a demo.", w)
	} else if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			return
		}
		session.username = r.FormValue("username")
		password := r.FormValue("password")
		if password == "" {
			renderTemplate("login.html", "Password required", w)
			return
		}
		if session.username == "" {
			renderTemplate("login.html", "Username required", w)
			return
		}
		// Step 2: Call the healthCheck to make sure UID is accessible

		action := "user.login"
		ip := GetIP(r)
		ua := r.Header.Get("User-Agent")
		_, err = client.HealthCheck(session.username, action, ip, ua)

		// Step 3: If UID is not available to authenticate then either allow user
		// to bypass UID (failopen) or prevent user from authenticating (failclosed)
		if err != nil {
			if session.failmode == "CLOSED" {
				renderTemplate("login.html", uidUnavailable, w)
			} else {
				renderTemplate("success.html", uidUnavailable, w)
			}
			return
		}

		// Step 4: Generate and save a state variable
		session.state, err = client.GenerateState()
		if err != nil {
			log.Fatal("Error generating state: ", err)
		}

		// Step 5: Create a URL to redirect to inorder to reach the UID prompt
		authURL, err := client.CreateAuthURL(session.username, session.state, action, ip, ua)
		if err != nil {
			log.Fatal("Error creating the auth URL: ", err)
		}

		// Step 6: Redirect to that prompt
		http.Redirect(w, r, authURL, 302)
	}
}

func (session *Session) callback(w http.ResponseWriter, r *http.Request, client *universal_sdk.Client) {
	// Step 7: Grab the state and code variables from the URL parameters
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	// Step 8: Verify that the state in the URL matches the state saved previously
	if state != session.state {
		renderTemplate("login.html", "UID state does not match saved state", w)
		return
	}

	// Step 9: Exchange the code from the URL parameters and the username of the user trying to authenticate
	// for an authentication token containing information about the auth
	authToken, err := client.GetTokenResponse(code, session.username)
	if err != nil {
		log.Fatal("Error exchanging authToken: ", err)
	}
	message, _ := json.MarshalIndent(authToken, " ", "    ")
	renderTemplate("success.html", string(message), w)
}

// Renders HTML page with message
func renderTemplate(fileName, message string, w http.ResponseWriter) {
	fp := path.Join("templates", fileName)
	tmpl, _ := template.ParseFiles(fp)
	tmpl.Execute(w, map[string]interface{}{
		"Message": message,
	})
}

func GetIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip != "" && net.ParseIP(ip) != nil {
		return ip
	}

	ip = r.Header.Get("X-Forwarded-For")
	for _, i := range strings.Split(ip, ",") {
		if net.ParseIP(i) != nil {
			return i
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(ip) != nil {
		return ip
	}

	return ""
}
