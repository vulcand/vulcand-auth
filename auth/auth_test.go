package auth

import (
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/vulcan/netutils"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/vulcan/request"
	. "github.com/mailgun/vulcand/Godeps/_workspace/src/launchpad.net/gocheck"
	"github.com/mailgun/vulcand/plugin"
	"net/http"
	"testing"
)

func TestCL(t *testing.T) { TestingT(t) }

type AuthSuite struct {
}

var _ = Suite(&AuthSuite{})

// One of the most important tests:
// Make sure the RateLimit spec is compatible and will be accepted by middleware registry
func (s *AuthSuite) TestSpecIsOK(c *C) {
	c.Assert(plugin.NewRegistry().AddSpec(GetSpec()), IsNil)
}

func (s *AuthSuite) TestNewConnLimitSuccess(c *C) {
	cl, err := NewAuth("user", "pass")
	c.Assert(cl, NotNil)
	c.Assert(err, IsNil)

	c.Assert(cl.String(), Not(Equals), "")

	out, err := cl.NewMiddleware()
	c.Assert(out, NotNil)
	c.Assert(err, IsNil)
}

func (s *AuthSuite) TestNewAuthBadParams(c *C) {
	// Empty pass
	_, err := NewAuth("user", "")
	c.Assert(err, NotNil)

	// Empty user
	_, err = NewAuth("", "pass")
	c.Assert(err, NotNil)
}

func (s *AuthSuite) TestAuthFromOther(c *C) {
	cl, err := NewAuth("user", "pass")
	c.Assert(cl, NotNil)
	c.Assert(err, IsNil)

	out, err := FromOther(*cl)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, cl)
}

func (s *AuthSuite) TestAuthFromCli(c *C) {
	app := cli.NewApp()
	app.Name = "test"
	executed := false
	app.Action = func(ctx *cli.Context) {
		executed = true
		out, err := FromCli(ctx)
		c.Assert(out, NotNil)
		c.Assert(err, IsNil)

		a := out.(*Auth)
		c.Assert(a.Password, Equals, "pass1")
		c.Assert(a.Username, Equals, "user1")
	}
	app.Flags = CliFlags()
	app.Run([]string{"test", "--user=user1", "--pass=pass1"})
	c.Assert(executed, Equals, true)
}

func (s *AuthSuite) TestRequestSuccess(c *C) {
	a := &Auth{Username: "Aladdin", Password: "open sesame"}
	out, err := a.ProcessRequest(makeRequest(a.Username, a.Password))
	c.Assert(out, IsNil)
	c.Assert(err, IsNil)
}

func (s *AuthSuite) TestRequestBadPassword(c *C) {
	a := &Auth{Username: "Aladdin", Password: "open sesame"}
	out, err := a.ProcessRequest(makeRequest(a.Username, "what?"))
	c.Assert(out, NotNil)
	c.Assert(err, IsNil)
}

func (s *AuthSuite) TestRequestMissingPass(c *C) {
	a := &Auth{Username: "Aladdin", Password: "open sesame"}
	out, err := a.ProcessRequest(&request.BaseRequest{HttpRequest: &http.Request{}})
	c.Assert(out, NotNil)
	c.Assert(err, IsNil)
}

func (s *AuthSuite) TestRequestBadPass(c *C) {
	request := &request.BaseRequest{
		HttpRequest: &http.Request{
			Method: "GET",
			Header: map[string][]string{
				"Authorization": []string{"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
			},
		},
	}
	a := &Auth{Username: "Aladdin", Password: "open sesame"}
	out, err := a.ProcessRequest(request)
	c.Assert(out, IsNil)
	c.Assert(err, IsNil)
}

func makeRequest(username string, password string) request.Request {
	return &request.BaseRequest{
		HttpRequest: &http.Request{
			Method: "GET",
			Header: map[string][]string{
				"Authorization": []string{(&netutils.BasicAuth{Username: username, Password: password}).String()},
			},
		},
	}
}
