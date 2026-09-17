package routes

import (
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-openapi/runtime/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/michaelquigley/pfxlog"
	enrollment_client "github.com/openziti/edge-api/rest_client_api_server/operations/enrollment"
	enrollment_management "github.com/openziti/edge-api/rest_management_api_server/operations/enrollment"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/openziti/ziti/v2/controller/env"
	"github.com/openziti/ziti/v2/controller/permissions"
	"github.com/openziti/ziti/v2/controller/response"
)

func init() {
	r := NewNetworkJwtRouter()
	env.AddRouter(r)
}

const (
	EntityNameNetworkJwt = "network-jwts"

	EnrollmentMethodNetwork = "network"

	DefaultNetworkJwtName = "default"
)

type NetworkJwtRoute struct {
	BasePath string

	// networkJwt caches the signed token. The endpoint needs no authentication, so several
	// requests can be in the handler at once, and the value has to be published safely rather
	// than assigned to a plain string. The lock makes the first request do the signing and the
	// rest wait for it, instead of each signing its own throwaway token.
	networkJwtLock sync.Mutex
	networkJwt     string
}

func NewNetworkJwtRouter() *NetworkJwtRoute {
	return &NetworkJwtRoute{
		BasePath: "/" + EntityNameNetworkJwt,
	}
}

func (r *NetworkJwtRoute) Register(ae *env.AppEnv) {

	ae.ManagementApi.EnrollmentListNetworkJWTsHandler = enrollment_management.ListNetworkJWTsHandlerFunc(func(params enrollment_management.ListNetworkJWTsParams) middleware.Responder {
		return ae.IsAllowed(r.List, params.HTTPRequest, "", "", permissions.Always())
	})

	ae.ClientApi.EnrollmentListNetworkJWTsHandler = enrollment_client.ListNetworkJWTsHandlerFunc(func(params enrollment_client.ListNetworkJWTsParams) middleware.Responder {
		return ae.IsAllowed(r.List, params.HTTPRequest, "", "", permissions.Always())
	})

}

func (r *NetworkJwtRoute) List(ae *env.AppEnv, rc *response.RequestContext) {
	networkJwt, err := r.getNetworkJwt(ae)

	if err != nil {
		rc.RespondWithError(err)
		return
	}

	name := DefaultNetworkJwtName
	resp := rest_model.ListNetworkJWTsEnvelope{
		Data: rest_model.NetworkJWTList{
			&rest_model.NetworkJWT{
				Name:  &name,
				Token: &networkJwt,
			},
		},
		Meta: &rest_model.Meta{},
	}

	rc.Respond(resp, http.StatusOK)
}

// getNetworkJwt returns the network JWT, signing it on first use.
func (r *NetworkJwtRoute) getNetworkJwt(ae *env.AppEnv) (string, error) {
	return r.cachedJwt(func() (string, error) {
		return signNetworkJwt(ae)
	})
}

// cachedJwt returns the cached token, calling generate once if there is none. A failed
// attempt is not cached, so the next request tries again.
func (r *NetworkJwtRoute) cachedJwt(generate func() (string, error)) (string, error) {
	r.networkJwtLock.Lock()
	defer r.networkJwtLock.Unlock()

	if r.networkJwt != "" {
		return r.networkJwt, nil
	}

	jwtStr, err := generate()

	if err != nil {
		return "", err
	}

	r.networkJwt = jwtStr

	return r.networkJwt, nil
}

func signNetworkJwt(ae *env.AppEnv) (string, error) {
	issuer := fmt.Sprintf(`https://%s/`, ae.GetConfig().Edge.Api.Address)

	claims := &ziti.EnrollmentClaims{
		EnrollmentMethod: EnrollmentMethodNetwork,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{env.JwtAudEnrollment},
			Issuer:   issuer,
			Subject:  issuer,
			ID:       uuid.NewString(),
		},
	}

	signer, err := ae.GetEnrollmentJwtSigner()

	if err != nil {
		pfxlog.Logger().WithError(err).Error("could not get enrollment signer to generate a network JWT")
		return "", errors.New("could not determine signer")
	}

	jwtStr, err := signer.Generate(claims)

	if err != nil {
		pfxlog.Logger().WithError(err).Error("could not sign network JWT")
		return "", errors.New("could not generate claims")
	}

	return jwtStr, nil
}
