package auth

// Note that I import the versions bundled with vulcand. That will make our lives easier, as we'll use exactly the same versions used
// by vulcand. Kind of escaping dependency management troubles thanks to Godep.
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
		Type:      Type,       // A short name for the middleware
		FromOther: FromOther,  // Tells vulcand how to rcreate middleware from another one (this is for deserialization)
		FromCli:   FromCli,    // Tells vulcand how to create middleware from command line tool
		CliFlags:  CliFlags(), // Vulcand will add this flags to middleware specific command line tool
	}
}

// Auth middleware
type Auth struct {
	Password string
	Username string
}

// This function will be called each time the request hits the location with this middleware activated
func (a *Auth) ProcessRequest(r Request) (*http.Response, error) {
	auth, err := netutils.ParseAuthHeader(r.GetHttpRequest().Header.Get("Authorization"))
	// We want to reject the request, so we create and return ``Forbidden`` response
	if err != nil || a.Username != auth.Username || a.Password != auth.Password {
		return netutils.NewTextResponse(r.GetHttpRequest(), http.StatusForbidden, "Forbidden"), nil
	}
	// Return a pair ``nil, nil`` indicates that we let the request continue
	// to the next middleware in chain or the endpoint
	return nil, nil
}

func (*Auth) ProcessResponse(r Request, a Attempt) {
}

// This function is optional but handy, used to check input parameters when creating new middlewares
func NewAuth(user, pass string) (*Auth, error) {
	if user == "" || pass == "" {
		return nil, fmt.Errorf("Username and password can not be empty")
	}
	return &Auth{Username: user, Password: pass}, nil
}

// This function is important, it's called by vulcand to create a new instance of the middleware and put it into the
// middleware chain for the location. In our case we just return our existing instance. In more complex cases you
// may want to return something else or construct a different object
func (r *Auth) NewMiddleware() (middleware.Middleware, error) {
	return r, nil
}

// Very insecure :-)
func (r *Auth) String() string {
	return fmt.Sprintf("username=%s, pass=%s", r.Username, r.Password)
}

// Will be called by Vulcand when backend or API will read the middleware from the serialized bytes.
// It's important that the signature of the function will be exactly the same, otherwise Vulcand will
// fail to register this middleware.
// The first and the only parameter should be the struct itself, no pointers and other variables.
// Function should return middleware interface and error in case if the parameters are wrong.
func FromOther(a Auth) (plugin.Middleware, error) {
	return NewAuth(a.Username, a.Password)
}

// Constructs the middleware from the command line
func FromCli(c *cli.Context) (plugin.Middleware, error) {
	return NewAuth(c.String("user"), c.String("pass"))
}

func CliFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{"user, u", "", "Basic auth username", ""},
		cli.StringFlag{"pass, p", "", "Basic auth pass", ""},
	}
}
