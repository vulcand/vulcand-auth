package auth

import (
	"fmt"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/vulcan/middleware"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/vulcan/netutils"
	. "github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/vulcan/request"
	"github.com/mailgun/vulcand/plugin"
	"net/http"
)

const Type = "auth"

func GetSpec() *plugin.MiddlewareSpec {
	return &plugin.MiddlewareSpec{
		Type:      Type,
		FromOther: FromOther,
		FromCli:   FromCli,
		CliFlags:  CliFlags(),
	}
}

// Auth middleware that requires authorization
type Auth struct {
	Password string
	Username string
}

func (a *Auth) ProcessRequest(r Request) (*http.Response, error) {
	auth, err := netutils.ParseAuthHeader(r.GetHttpRequest().Header.Get("Authorization"))
	if err != nil || a.Username != auth.Username || a.Password != auth.Password {
		return netutils.NewTextResponse(r.GetHttpRequest(), http.StatusForbidden, "Forbidden"), nil
	}
	return nil, nil
}

func (*Auth) ProcessResponse(r Request, a Attempt) {
}

func NewAuth(user, pass string) (*Auth, error) {
	if user == "" || pass == "" {
		return nil, fmt.Errorf("Username and password can not be empty")
	}
	return &Auth{Username: user, Password: pass}, nil
}

// Returns vulcan library compatible middleware
func (r *Auth) NewMiddleware() (middleware.Middleware, error) {
	return r, nil
}

// Very insecure :-)
func (r *Auth) String() string {
	return fmt.Sprintf("username=%s, pass=%s", r.Username, r.Password)
}

func FromOther(a Auth) (plugin.Middleware, error) {
	return NewAuth(a.Username, a.Password)
}

// Constructs the middleware from the command line
func FromCli(c *cli.Context) (plugin.Middleware, error) {
	return NewAuth(c.String("user"), c.String("pass"))
}

func CliFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{"user, u", "", "Basic auth username"},
		cli.StringFlag{"pass, p", "", "Basic auth pass"},
	}
}
