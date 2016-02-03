package auth

// Note that I import the versions bundled with vulcand. That will make our lives easier, as we'll use exactly the same versions used
// by vulcand. We are escaping dependency management troubles thanks to Godep.
import (
	"fmt"
	"io"
	"net/http"

	"github.com/vulcand/vulcand/vendor/github.com/codegangsta/cli"
	"github.com/vulcand/vulcand/vendor/github.com/vulcand/oxy/utils"
	"github.com/vulcand/vulcand/plugin"
)

const Type = "auth"

func GetSpec() *plugin.MiddlewareSpec {
	return &plugin.MiddlewareSpec{
		Type:      Type,       // A short name for the middleware
		FromOther: FromOther,  // Tells vulcand how to rcreate middleware from another one (this is for deserialization)
		FromCli:   FromCli,    // Tells vulcand how to create middleware from command line tool
		CliFlags:  CliFlags(), // Vulcand will add this flags to middleware specific command line tool
	}
}

// AuthMiiddleware struct holds configuration parameters and is used to
// serialize/deserialize the configuration from storage engines.
type AuthMiddleware struct {
	Password string
	Username string
}

// Auth middleware handler
type AuthHandler struct {
	cfg  AuthMiddleware
	next http.Handler
}

// This function will be called each time the request hits the location with this middleware activated
func (a *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth, err := utils.ParseAuthHeader(r.Header.Get("Authorization"))
	// Reject the request by writing forbidden response
	if err != nil || a.cfg.Username != auth.Username || a.cfg.Password != auth.Password {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "Forbidden")
		return
	}
	// Pass the request to the next middleware in chain
	a.next.ServeHTTP(w, r)
}

// This function is optional but handy, used to check input parameters when creating new middlewares
func New(user, pass string) (*AuthMiddleware, error) {
	if user == "" || pass == "" {
		return nil, fmt.Errorf("Username and password can not be empty")
	}
	return &AuthMiddleware{Username: user, Password: pass}, nil
}

// This function is important, it's called by vulcand to create a new handler from the middleware config and put it into the
// middleware chain. Note that we need to remember 'next' handler to call
func (c *AuthMiddleware) NewHandler(next http.Handler) (http.Handler, error) {
	return &AuthHandler{next: next, cfg: *c}, nil
}

// String() will be called by loggers inside Vulcand and command line tool.
func (c *AuthMiddleware) String() string {
	return fmt.Sprintf("username=%v, pass=%v", c.Username, "********")
}

// FromOther Will be called by Vulcand when engine or API will read the middleware from the serialized format.
// It's important that the signature of the function will be exactly the same, otherwise Vulcand will
// fail to register this middleware.
// The first and the only parameter should be the struct itself, no pointers and other variables.
// Function should return middleware interface and error in case if the parameters are wrong.
func FromOther(c AuthMiddleware) (plugin.Middleware, error) {
	return New(c.Username, c.Password)
}

// FromCli constructs the middleware from the command line
func FromCli(c *cli.Context) (plugin.Middleware, error) {
	return New(c.String("user"), c.String("pass"))
}

// CliFlags will be used by Vulcand construct help and CLI command for the vctl command
func CliFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{"user, u", "", "Basic auth username", ""},
		cli.StringFlag{"pass, p", "", "Basic auth pass", ""},
	}
}
