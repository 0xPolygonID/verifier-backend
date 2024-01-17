package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	auth "github.com/iden3/go-iden3-auth/v2"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"

	"github.com/0xPolygonID/verifier-backend/internal/common"
	"github.com/0xPolygonID/verifier-backend/internal/config"
	"github.com/0xPolygonID/verifier-backend/internal/loader"
)

const (
	randomSeed           = 1000000
	stateTransitionDelay = time.Minute * 5
	statusPending        = "pending"
	statusSuccess        = "success"
	statusError          = "error"
)

// Server represents the API server
type Server struct {
	keyLoader *loaders.FSKeyLoader
	cfg       config.Config
	cache     *cache.Cache
}

// New creates a new API server
func New(cfg config.Config, keyLoader *loaders.FSKeyLoader) *Server {
	return &Server{
		cfg:       cfg,
		keyLoader: keyLoader,
		cache:     cache.New(cfg.CacheExpiration.AsDuration(), cfg.CacheExpiration.AsDuration()),
	}
}

// RegisterStatic add method to the mux that are not documented in the API.
func RegisterStatic(mux *chi.Mux) {
	mux.Get("/", documentation)
	mux.Get("/static/docs/api/api.yaml", swagger)
	mux.Get("/favicon.ico", favicon)
}

// Health is a method
func (s *Server) Health(_ context.Context, _ HealthRequestObject) (HealthResponseObject, error) {
	var resp Health200JSONResponse = Health{"healthy": true}
	return resp, nil
}

// GetDocumentation this method will be overridden in the main function
func (s *Server) GetDocumentation(_ context.Context, _ GetDocumentationRequestObject) (GetDocumentationResponseObject, error) {
	return nil, nil
}

// Callback - handle callback endpoint
func (s *Server) Callback(ctx context.Context, request CallbackRequestObject) (CallbackResponseObject, error) {
	sessionID := request.Params.SessionID

	log.WithFields(log.Fields{
		"sessionID": sessionID,
		"token":     request.Body,
	}).Info("callback")

	authRequest, b := s.cache.Get(sessionID.String())
	if !b {
		log.WithFields(log.Fields{
			"sessionID": sessionID,
		}).Error("sessionID not found")
		return nil, fmt.Errorf("sessionID not found")
	}

	w3cLoader := loader.NewW3CDocumentLoader(nil, s.cfg.IPFSURL)

	resolvers := s.parseResolverSettings()
	verifier, err := auth.NewVerifier(s.keyLoader, resolvers, auth.WithDocumentLoader(w3cLoader))
	if err != nil {
		log.WithFields(log.Fields{
			"sessionID": sessionID,
			"err":       err,
		}).Error("failed to create verifier")
		return nil, err
	}

	_, err = verifier.FullVerify(ctx, *request.Body,
		authRequest.(protocol.AuthorizationRequestMessage),
		pubsignals.WithAcceptedStateTransitionDelay(stateTransitionDelay))
	if err != nil {
		log.WithFields(log.Fields{
			"sessionID": sessionID,
			"err":       err,
		}).Error("failed to verify")
		s.cache.Set(sessionID.String(), err, cache.DefaultExpiration)
		return nil, err
	}

	s.cache.Set(sessionID.String(), *request.Body, cache.DefaultExpiration)

	return Callback200JSONResponse{}, nil
}

// GetQRCodeFromStore - get QR code from store
func (s *Server) GetQRCodeFromStore(ctx context.Context, request GetQRCodeFromStoreRequestObject) (GetQRCodeFromStoreResponseObject, error) {
	sessionID := request.Params.Id
	data, ok := s.cache.Get(sessionID.String())
	if !ok {
		log.Println("sessionID not found")
		return GetQRCodeFromStore500JSONResponse{
			N500JSONResponse: N500JSONResponse{
				Message: "sessionID not found",
			},
		}, nil
	}

	response, ok := data.(*QRCode)
	if !ok {
		log.Println("failed to cast data to QRCode")
		return GetQRCodeFromStore500JSONResponse{
			N500JSONResponse: N500JSONResponse{
				Message: "failed to cast data to QRCode",
			},
		}, nil
	}
	return GetQRCodeFromStore200JSONResponse(*response), nil
}

// QRStore - store QR code
func (s *Server) QRStore(ctx context.Context, request QRStoreRequestObject) (QRStoreResponseObject, error) {
	if request.Body.Body.CallbackUrl == "" {
		return QRStore400JSONResponse{
			N400JSONResponse: N400JSONResponse{
				Message: "field callbackUrl body is empty",
			},
		}, nil
	}

	if request.Body.Body.Reason == "" {
		return QRStore400JSONResponse{
			N400JSONResponse: N400JSONResponse{
				Message: "field reason body is empty",
			},
		}, nil
	}

	if len(request.Body.Body.Scope) == 0 {
		return QRStore400JSONResponse{
			N400JSONResponse: N400JSONResponse{
				Message: "field scope is empty",
			},
		}, nil
	}

	if request.Body.From == "" {
		return QRStore400JSONResponse{
			N400JSONResponse: N400JSONResponse{
				Message: "field from is empty",
			},
		}, nil
	}

	if request.Body.Id == "" {
		return QRStore400JSONResponse{
			N400JSONResponse: N400JSONResponse{
				Message: "field id is empty",
			},
		}, nil
	}

	if request.Body.Thid == "" {
		return QRStore400JSONResponse{
			N400JSONResponse: N400JSONResponse{
				Message: "field thid is empty",
			},
		}, nil
	}

	if request.Body.Typ == "" {
		return QRStore400JSONResponse{
			N400JSONResponse: N400JSONResponse{
				Message: "field Typ is empty",
			},
		}, nil
	}

	if request.Body.Type == "" {
		return QRStore400JSONResponse{
			N400JSONResponse: N400JSONResponse{
				Message: "field type is empty",
			},
		}, nil
	}

	uv := uuid.New()
	s.cache.Set(uv.String(), request.Body, 1*time.Hour)
	hostURL := s.cfg.Host
	shortURL := fmt.Sprintf("iden3comm://?request_uri=%s%s?id=%s", hostURL, "/qr-store", uv.String())
	return QRStore200JSONResponse(shortURL), nil
}

// SignIn - sign in
func (s *Server) SignIn(ctx context.Context, request SignInRequestObject) (SignInResponseObject, error) {
	rURL := s.cfg.Host

	check, err := checkRequest(request)
	if err != nil {
		return nil, err
	}

	if check != nil {
		return check, nil
	}

	sessionID := uuid.New()
	uri := fmt.Sprintf("%s%s?sessionID=%s", rURL, config.CallbackURL, sessionID)

	var senderDID string
	if request.Body.ChainID == "80001" {
		senderDID = s.cfg.MumbaiSenderDID
	} else {
		senderDID = s.cfg.MainSenderDID
	}

	authorizationRequest := auth.CreateAuthorizationRequest("test flow", senderDID, uri)

	// TODO - Ask when could be false
	isLocal := true
	if isLocal {
		authorizationRequest.ID = "7f38a193-0918-4a48-9fac-36adfdb8b542"
		authorizationRequest.ThreadID = "7f38a193-0918-4a48-9fac-36adfdb8b542"
	}

	// TODO: Why ID is 1. Ask
	mtpProofRequest := protocol.ZeroKnowledgeProofRequest{
		ID:        uint32(1),
		CircuitID: request.Body.CircuitID,
		Query:     request.Body.Query,
	}

	authorizationRequest.To = ""
	if request.Body.To != nil {
		authorizationRequest.To = *request.Body.To
	}

	authorizationRequest.Body.Scope = append(authorizationRequest.Body.Scope, mtpProofRequest)
	s.cache.Set(sessionID.String(), authorizationRequest, cache.DefaultExpiration)

	response := SignIn200JSONResponse{
		QrCode:    getQRCode(authorizationRequest),
		SessionID: sessionID,
	}

	return response, nil
}

func getQRCode(request protocol.AuthorizationRequestMessage) QRCode {
	scopes := make([]Scope, len(request.Body.Scope))
	for i, scope := range request.Body.Scope {
		scopes[i] = Scope{
			CircuitId: scope.CircuitID,
			Id:        int(scope.ID),
			Query:     scope.Query,
		}
	}

	type bodyType struct {
		CallbackUrl string  `json:"callbackUrl"`
		Reason      string  `json:"reason"`
		Scope       []Scope `json:"scope"`
	}

	body := bodyType{
		CallbackUrl: request.Body.CallbackURL,
		Reason:      request.Body.Reason,
		Scope:       scopes,
	}

	qrCode := QRCode{
		From: request.From,
		Id:   request.ID,
		Thid: request.ThreadID,
		Typ:  string(request.Typ),
		Type: string(request.Type),
		Body: body,
	}

	if request.To == "" {
		qrCode.To = nil
	} else {
		qrCode.To = &request.To
	}

	return qrCode
}

// Status - status
func (s *Server) Status(_ context.Context, request StatusRequestObject) (StatusResponseObject, error) {
	id := request.Params.SessionID
	item, ok := s.cache.Get(id.String())
	if !ok {
		log.WithFields(log.Fields{
			"sessionID": id,
		}).Error("sessionID not found")
		return Status404JSONResponse{
			N404JSONResponse: N404JSONResponse{
				Message: "sessionID not found",
			},
		}, nil
	}

	switch value := item.(type) {
	case protocol.AuthorizationRequestMessage:
		return Status200JSONResponse{
			Status: statusPending,
		}, nil
	case error:
		return Status200JSONResponse{
			Status:  statusError,
			Message: common.ToPointer(value.Error()),
		}, nil
	case string:
		b, err := json.Marshal(value)
		if err != nil {
			log.Println(err.Error())
			return Status500JSONResponse{
				N500JSONResponse: N500JSONResponse{
					Message: "failed to marshal response",
				},
			}, nil
		}
		//nolint // -
		var m string
		err = json.Unmarshal(b, &m)
		if err != nil {
			log.Errorf("failed to unmarshal response: %v", err)
			return Status500JSONResponse{
				N500JSONResponse: N500JSONResponse{
					Message: "failed to unmarshal response",
				},
			}, nil
		}
		return Status200JSONResponse{
			Status: statusSuccess,
			Jwz:    common.ToPointer(m),
		}, nil
	}
	return nil, nil
}

func documentation(w http.ResponseWriter, _ *http.Request) {
	writeFile("api/spec.html", "text/html; charset=UTF-8", w)
}

func favicon(w http.ResponseWriter, _ *http.Request) {
	writeFile("api/polygon.png", "image/png", w)
}

func swagger(w http.ResponseWriter, _ *http.Request) {
	writeFile("api/api.yaml", "text/html; charset=UTF-8", w)
}

func writeFile(path string, mimeType string, w http.ResponseWriter) {
	f, err := os.ReadFile(path)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}
	w.Header().Set("Content-Type", mimeType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(f)
}

// parseResolverSettings parses the resolver settings from the config file
func (s *Server) parseResolverSettings() map[string]pubsignals.StateResolver {
	resolvers := map[string]pubsignals.StateResolver{}
	for chainName, chainSettings := range s.cfg.ResolverSettings {
		for networkName, networkSettings := range chainSettings {
			prefix := fmt.Sprintf("%s:%s", chainName, networkName)
			resolver := state.NewETHResolver(networkSettings.NetworkURL, networkSettings.ContractAddress)
			resolvers[prefix] = resolver
		}
	}
	return resolvers
}

func checkRequest(request SignInRequestObject) (SignInResponseObject, error) {
	if request.Body.ChainID != "80001" && request.Body.ChainID != "137" {
		log.WithFields(log.Fields{
			"network": request.Body.ChainID,
		}).Error("invalid Chain ID - must be 80001 or 137")

		return SignIn400JSONResponse{N400JSONResponse: N400JSONResponse{
			Message: "invalid Chain ID - must be 80001 or 137",
		}}, nil
	}

	if request.Body.CircuitID != "credentialAtomicQuerySigV2" && request.Body.CircuitID != "credentialAtomicQueryMTPV2" {
		log.WithFields(log.Fields{
			"circuitID": request.Body.CircuitID,
		}).Error("invalid circuitID")
		return SignIn400JSONResponse{N400JSONResponse: N400JSONResponse{
			Message: "invalid circuitID, just credentialAtomicQuerySigV2 and credentialAtomicQueryMTPV2 are supported",
		}}, nil
	}

	query := request.Body.Query
	if query == nil {
		log.Error("query is nil")
		return SignIn400JSONResponse{N400JSONResponse: N400JSONResponse{
			Message: "query is nil",
		}}, nil
	}

	if query["context"] == nil || query["context"] == "" {
		log.Error("context is empty")
		return SignIn400JSONResponse{N400JSONResponse: N400JSONResponse{
			Message: "context is empty",
		}}, nil
	}

	if query["type"] == nil || query["type"] == "" {
		log.Error("type is empty")
		return SignIn400JSONResponse{N400JSONResponse: N400JSONResponse{
			Message: "type is empty",
		}}, nil
	}

	if query["allowedIssuers"] == nil {
		log.Error("allowedIssuers is nil")
		return SignIn400JSONResponse{N400JSONResponse: N400JSONResponse{
			Message: "allowedIssuers is empty",
		}}, nil
	}

	if query["credentialSubject"] == nil {
		log.Error("credentialSubject is nil")
		return SignIn400JSONResponse{N400JSONResponse: N400JSONResponse{
			Message: "credentialSubject is empty",
		}}, nil
	}

	return nil, nil
}
