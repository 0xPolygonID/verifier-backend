package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iden3/go-circuits/v2"
	auth "github.com/iden3/go-iden3-auth/v2"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-jwz/v2"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"

	"github.com/0xPolygonID/verifier-backend/internal/common"
	"github.com/0xPolygonID/verifier-backend/internal/config"
	"github.com/0xPolygonID/verifier-backend/internal/models"
)

const (
	stateTransitionDelay = time.Minute * 5
	statusPending        = "pending"
	statusSuccess        = "success"
	statusError          = "error"
	defaultReason        = "for testing purposes"
	defaultBigIntBase    = 10
)

// Server represents the API server
type Server struct {
	cfg        config.Config
	qrStore    *QRcodeStore
	cache      *cache.Cache
	verifier   *auth.Verifier
	senderDIDs map[string]string
}

// New creates a new API server
func New(cfg config.Config, verifier *auth.Verifier, senderDIDs map[string]string, cache *cache.Cache) *Server {
	return &Server{
		cfg:        cfg,
		qrStore:    NewQRCodeStore(cache),
		cache:      cache,
		verifier:   verifier,
		senderDIDs: senderDIDs,
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

	if _, ok := authRequest.(protocol.AuthorizationRequestMessage); !ok {
		log.Error("failed to cast authRequest to AuthorizationRequestMessage")
		return Callback500JSONResponse{
			N500JSONResponse: N500JSONResponse{
				Message: "failed to cast authRequest to AuthorizationRequestMessage",
			},
		}, nil
	}

	authRespMsg, err := s.verifier.FullVerify(ctx, *request.Body,
		authRequest.(protocol.AuthorizationRequestMessage),
		pubsignals.WithAcceptedStateTransitionDelay(stateTransitionDelay))
	if err != nil {
		log.WithFields(log.Fields{
			"sessionID": sessionID,
			"err":       err,
		}).Error("failed to verify")
		s.cache.Set(sessionID.String(), err, cache.DefaultExpiration)
		return Callback500JSONResponse{
			N500JSONResponse: N500JSONResponse{
				Message: err.Error(),
			},
		}, nil
	}

	scopes, err := getVerificationResponseScopes(authRespMsg.Body.Scope)
	if err != nil {
		return Callback500JSONResponse{
			N500JSONResponse: N500JSONResponse{
				Message: err.Error(),
			},
		}, nil
	}

	s.cache.Set(sessionID.String(), models.VerificationResponse{Jwz: *request.Body, UserDID: authRespMsg.From, Scopes: scopes}, cache.DefaultExpiration)

	return Callback200JSONResponse{}, nil
}

// GetQRCodeFromStore - get QR code from store
func (s *Server) GetQRCodeFromStore(_ context.Context, request GetQRCodeFromStoreRequestObject) (GetQRCodeFromStoreResponseObject, error) {
	qrCode, err := s.qrStore.Get(request.Params.Id)
	if err != nil {
		return GetQRCodeFromStore500JSONResponse{
			N500JSONResponse: N500JSONResponse{
				Message: fmt.Sprintf("Error getting QRCode: %s", err.Error()),
			},
		}, nil
	}
	return GetQRCodeFromStore200JSONResponse(*qrCode), nil
}

// SignIn - sign in
func (s *Server) SignIn(_ context.Context, request SignInRequestObject) (SignInResponseObject, error) {
	sessionID := uuid.New()

	if len(request.Body.Scope) == 0 {
		log.Error("field scope is empty")
		return SignIn400JSONResponse{N400JSONResponse{Message: "field scope is empty"}}, nil
	}

	switch circuits.CircuitID(request.Body.Scope[0].CircuitId) {
	case circuits.AtomicQuerySigV2CircuitID, circuits.AtomicQueryMTPV2CircuitID, circuits.AtomicQueryV3CircuitID:
		authReq, err := s.getAuthRequestOffChain(request, sessionID)
		if err != nil {
			log.Error(err)
			return SignIn400JSONResponse{N400JSONResponse{err.Error()}}, nil
		}
		s.cache.Set(sessionID.String(), authReq, cache.DefaultExpiration)
		qrCode := getAuthReqQRCode(authReq)
		qrID, err := s.qrStore.Save(qrCode)
		if err != nil {
			return SignIn500JSONResponse{N500JSONResponse{Message: fmt.Sprintf("failed to cache QR code: %s", err.Error())}}, nil
		}
		return SignIn200JSONResponse{
			QrCode:    fmt.Sprintf("iden3comm://?request_uri=%s%s?id=%s", s.cfg.Host, "/qr-store", qrID.String()),
			SessionID: sessionID,
		}, nil
	case circuits.AtomicQuerySigV2OnChainCircuitID, circuits.AtomicQueryMTPV2OnChainCircuitID, circuits.AtomicQueryV3OnChainCircuitID:
		invokeReq, err := s.getContractInvokeRequestOnChain(request)
		if err != nil {
			log.Error(err)
			return SignIn400JSONResponse{N400JSONResponse{err.Error()}}, nil
		}
		s.cache.Set(sessionID.String(), invokeReq, cache.DefaultExpiration)
		qrCode := getInvokeContractQRCode(invokeReq)
		qrID, err := s.qrStore.Save(qrCode)
		if err != nil {
			return SignIn500JSONResponse{N500JSONResponse{Message: fmt.Sprintf("failed to cache QR code: %s", err.Error())}}, nil
		}
		return SignIn200JSONResponse{
			QrCode:    fmt.Sprintf("iden3comm://?request_uri=%s%s?id=%s", s.cfg.Host, "/qr-store", qrID.String()),
			SessionID: sessionID,
		}, nil
	default:
		log.Errorf("invalid circuitID: %s", request.Body.Scope[0].CircuitId)
		return SignIn400JSONResponse{N400JSONResponse{Message: "invalid circuitID"}}, nil
	}
}

// Status - status
func (s *Server) Status(_ context.Context, request StatusRequestObject) (StatusResponseObject, error) {
	id := request.Params.SessionID
	item, ok := s.cache.Get(id.String())
	if !ok {
		log.WithFields(log.Fields{"sessionID": id}).Error("sessionID not found")
		return Status404JSONResponse{N404JSONResponse: N404JSONResponse{Message: "sessionID not found"}}, nil
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
	case models.VerificationResponse:
		vps, err := getVerifiablePresentations(value.Jwz)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("failed to get verifiable presentations")
			return Status200JSONResponse{
				Status:  statusError,
				Message: common.ToPointer(err.Error()),
			}, nil
		}
		return getStatusVerificationResponse(value, vps), nil
	default:
		return Status404JSONResponse{
			N404JSONResponse{
				Message: "unexpected object in the session storage",
			},
		}, nil
	}
}

func getVerifiablePresentations(jwzToken string) (VerifiablePresentations, error) {
	token, err := jwz.Parse(jwzToken)
	if err != nil {
		return nil, err
	}

	var payload models.JWZPayload
	if err := json.Unmarshal(token.GetPayload(), &payload); err != nil {
		return nil, err
	}

	resp := make(VerifiablePresentations, 0, len(payload.Body.Scope))
	for _, scope := range payload.Body.Scope {
		if scope.Vp.VerifiableCredential.CredentialSubject == nil {
			continue
		}
		resp = append(resp, VerifiablePresentation{
			CredentialSubject: scope.Vp.VerifiableCredential.CredentialSubject,
			ProofType:         scope.Vp.Type,
			SchemaContext:     scope.Vp.VerifiableCredential.Context,
			SchemaType:        scope.Vp.VerifiableCredential.Type,
		})
	}
	return resp, nil
}

func documentation(w http.ResponseWriter, _ *http.Request) {
	writeFile("api/spec.html", "text/html; charset=UTF-8", w)
}

func favicon(w http.ResponseWriter, _ *http.Request) {
	writeFile("api/privadoid.png", "image/png", w)
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

func getAuthReqQRCode(request protocol.AuthorizationRequestMessage) QRCode {
	scopes := make([]Scope, 0, len(request.Body.Scope))
	for _, scope := range request.Body.Scope {
		sc := Scope{
			CircuitId: scope.CircuitID,
			Id:        scope.ID,
			Query:     scope.Query,
		}
		if scope.Params != nil {
			sc.Params = common.ToPointer(scope.Params)
		}
		scopes = append(scopes, sc)
	}

	qrCode := QRCode{
		From: request.From,
		Id:   request.ID,
		Thid: request.ThreadID,
		Typ:  string(request.Typ),
		Type: string(request.Type),
		Body: Body{
			CallbackUrl: common.ToPointer(request.Body.CallbackURL),
			Reason:      request.Body.Reason,
			Scope:       scopes,
		},
	}
	if request.To != "" {
		qrCode.To = &request.To
	}

	return qrCode
}

func getInvokeContractQRCode(request protocol.ContractInvokeRequestMessage) QRCode {
	scopes := make([]Scope, 0, len(request.Body.Scope))
	for _, scope := range request.Body.Scope {
		sc := Scope{
			CircuitId: scope.CircuitID,
			Id:        scope.ID,
			Query:     scope.Query,
		}
		if scope.Params != nil {
			sc.Params = common.ToPointer(scope.Params)
		}
		scopes = append(scopes, sc)
	}

	qrCode := QRCode{
		From: request.From,
		Id:   request.ID,
		Thid: request.ThreadID,
		Typ:  string(request.Typ),
		Type: string(request.Type),
		Body: Body{
			Reason: request.Body.Reason,
			Scope:  scopes,
			TransactionData: &TransactionDataResponse{
				ChainId:         request.Body.TransactionData.ChainID,
				ContractAddress: request.Body.TransactionData.ContractAddress,
				MethodId:        request.Body.TransactionData.MethodID,
				Network:         request.Body.TransactionData.Network,
			},
		},
	}
	if request.To != "" {
		qrCode.To = &request.To
	}

	return qrCode
}

func validateOffChainRequest(request SignInRequestObject) error {
	if request.Body.ChainID == nil {
		return errors.New("field chainId is empty")
	}

	if err := validateRequestQuery(true, request.Body.Scope); err != nil {
		return err
	}

	return nil
}

func validateRequestQuery(offChainRequest bool, scope []ScopeRequest) error {
	reqIds := make(map[uint32]bool, 0)
	for _, scope := range scope {
		if reqIds[scope.Id] {
			return fmt.Errorf("field scope id must be unique, got %d multiple times", scope.Id)
		}
		reqIds[scope.Id] = true

		if scope.Id <= 0 {
			return errors.New("field scope id is empty")
		}

		if scope.CircuitId == "" {
			return errors.New("field circuitId is empty")
		}

		circuitID := circuits.CircuitID(scope.CircuitId)
		if offChainRequest {
			if circuitID != circuits.AtomicQuerySigV2CircuitID && circuitID != circuits.AtomicQueryMTPV2CircuitID && circuitID != circuits.AtomicQueryV3CircuitID {
				return fmt.Errorf("field circuitId value is wrong, got %s, expected %s or %s or %s", scope.CircuitId, circuits.AtomicQuerySigV2CircuitID, circuits.AtomicQueryMTPV2CircuitID, circuits.AtomicQueryV3CircuitID)
			}
		}

		if !offChainRequest {
			if circuitID != circuits.AtomicQuerySigV2OnChainCircuitID && circuitID != circuits.AtomicQueryMTPV2OnChainCircuitID && circuitID != circuits.AtomicQueryV3OnChainCircuitID {
				return fmt.Errorf("field circuitId value is wrong, got %s, expected %s or %s or %s", scope.CircuitId, circuits.AtomicQuerySigV2OnChainCircuitID, circuits.AtomicQueryMTPV2OnChainCircuitID, circuits.AtomicQueryV3OnChainCircuitID)
			}
		}

		if scope.Query == nil {
			return errors.New("field query is empty")
		}

		if scope.Query["context"] == nil || scope.Query["context"] == "" {
			return errors.New("context cannot be empty")
		}

		if scope.Query["type"] == nil || scope.Query["type"] == "" {
			return errors.New("type cannot be empty")
		}

		if scope.Query["allowedIssuers"] == nil {
			return errors.New("allowedIssuers cannot be empty")
		}
	}

	return nil
}

func (s *Server) getAuthRequestOffChain(req SignInRequestObject, sessionID uuid.UUID) (protocol.AuthorizationRequestMessage, error) {
	if err := validateOffChainRequest(req); err != nil {
		return protocol.AuthorizationRequestMessage{}, err
	}

	senderDID, err := s.getSenderDID(*req.Body.ChainID)
	if err != nil {
		return protocol.AuthorizationRequestMessage{}, err
	}

	id := uuid.NewString()
	authReq := auth.CreateAuthorizationRequest(getReason(req.Body.Reason), senderDID, getUri(s.cfg, sessionID))
	authReq.ID = id
	authReq.ThreadID = id
	authReq.To = ""
	if req.Body.To != nil {
		authReq.To = *req.Body.To
	}

	for _, scope := range req.Body.Scope {
		mtpProofRequest := protocol.ZeroKnowledgeProofRequest{
			ID:        scope.Id,
			CircuitID: scope.CircuitId,
			Query:     scope.Query,
		}
		if scope.Params != nil {
			params, err := getParams(*scope.Params)
			if err != nil {
				return protocol.AuthorizationRequestMessage{}, err
			}

			mtpProofRequest.Params = params
		}
		authReq.Body.Scope = append(authReq.Body.Scope, mtpProofRequest)
	}
	return authReq, nil
}

func checkOnChainRequest(req SignInRequestObject) error {
	if err := validateRequestQuery(false, req.Body.Scope); err != nil {
		return err
	}

	if req.Body.TransactionData == nil {
		return errors.New("field transactionData is empty")
	}

	if req.Body.TransactionData.ChainID <= 0 {
		return errors.New("field chainId is empty")
	}

	if req.Body.TransactionData.ContractAddress == "" {
		return errors.New("field contractAddress is empty")
	}

	if req.Body.TransactionData.MethodID == "" {
		return errors.New("field methodId is empty")
	}

	if req.Body.TransactionData.Network == "" {
		return errors.New("field network is empty")
	}

	return nil
}

func (s *Server) getContractInvokeRequestOnChain(req SignInRequestObject) (protocol.ContractInvokeRequestMessage, error) {
	if err := checkOnChainRequest(req); err != nil {
		return protocol.ContractInvokeRequestMessage{}, err
	}

	mtpProofRequests := make([]protocol.ZeroKnowledgeProofRequest, 0, len(req.Body.Scope))
	for _, scope := range req.Body.Scope {
		zkProofReq := protocol.ZeroKnowledgeProofRequest{
			ID:        scope.Id,
			CircuitID: scope.CircuitId,
			Query:     scope.Query,
		}
		if scope.Params != nil {
			params, err := getParams(*scope.Params)
			if err != nil {
				return protocol.ContractInvokeRequestMessage{}, err
			}
			zkProofReq.Params = params
		}
		mtpProofRequests = append(mtpProofRequests, zkProofReq)
	}

	transactionData := protocol.TransactionData{
		ContractAddress: req.Body.TransactionData.ContractAddress,
		MethodID:        req.Body.TransactionData.MethodID,
		ChainID:         req.Body.TransactionData.ChainID,
		Network:         req.Body.TransactionData.Network,
	}
	senderDID, err := s.getSenderDID(strconv.Itoa(transactionData.ChainID))
	if err != nil {
		return protocol.ContractInvokeRequestMessage{}, err
	}

	authReq := auth.CreateContractInvokeRequest(getReason(req.Body.Reason), senderDID, transactionData, mtpProofRequests...)
	id := uuid.NewString()
	authReq.ID = id
	authReq.ThreadID = id
	authReq.To = ""

	verifierDID, err := buildOnchainVerifierDID(transactionData)
	if err != nil {
		return protocol.ContractInvokeRequestMessage{}, err
	}

	authReq.From = verifierDID.String()
	if req.Body.To != nil {
		authReq.To = *req.Body.To
	}

	return authReq, nil
}

func buildOnchainVerifierDID(transactionData protocol.TransactionData) (*w3c.DID, error) {
	address := common2.HexToAddress(transactionData.ContractAddress)
	var ethAddr [20]byte
	copy(ethAddr[:], address.Bytes())

	currentState := core.GenesisFromEthAddress(ethAddr)

	blockchain, network, err := core.NetworkByChainID(core.ChainID(transactionData.ChainID))
	if err != nil {
		return nil, err
	}
	didType, err := core.BuildDIDType(core.DIDMethodPolygonID, blockchain, network)
	if err != nil {
		return nil, err
	}

	did, err := core.NewDID(didType, currentState)
	if err != nil {
		return nil, err
	}
	return did, nil
}

func getParams(params ScopeParams) (map[string]interface{}, error) {
	val, ok := params["nullifierSessionID"]
	if !ok {
		return nil, errors.New("nullifierSessionID is empty")
	}

	nullifierSessionID := new(big.Int)
	if _, ok := nullifierSessionID.SetString(val.(string), defaultBigIntBase); !ok {
		return nil, errors.New("nullifierSessionID is not a valid big integer")
	}

	return map[string]interface{}{"nullifierSessionId": nullifierSessionID.String()}, nil
}

func (s *Server) getSenderDID(chainID string) (string, error) {
	val, ok := s.senderDIDs[chainID]
	if !ok {
		return "", fmt.Errorf("sender not found for chainID %s", chainID)
	}

	return val, nil
}

func getUri(cfg config.Config, sessionID uuid.UUID) string {
	return fmt.Sprintf("%s%s?sessionID=%s", cfg.Host, config.CallbackURL, sessionID)
}

func getReason(reason *string) string {
	if reason == nil {
		return defaultReason
	}
	return *reason
}

func getVerificationResponseScopes(scopes []protocol.ZeroKnowledgeProofResponse) ([]models.VerificationResponseScope, error) {
	if len(scopes) == 0 {
		return nil, errors.New("scopes are empty")
	}

	if scopes[0].CircuitID != string(circuits.AtomicQueryV3CircuitID) {
		return []models.VerificationResponseScope{}, nil
	}

	resp := make([]models.VerificationResponseScope, 0, len(scopes))
	for _, scope := range scopes {
		ps := circuits.AtomicQueryV3PubSignals{}
		if scope.CircuitID != string(circuits.AtomicQueryV3CircuitID) {
			return []models.VerificationResponseScope{}, nil
		}

		signals, err := json.Marshal(scope.PubSignals)
		if err != nil {
			return nil, err
		}

		if err := ps.PubSignalsUnmarshal(signals); err != nil {
			return nil, err
		}

		resp = append(resp, models.VerificationResponseScope{
			ID:                 scope.ID,
			NullifierSessionID: ps.NullifierSessionID.String(),
			Nullifier:          ps.Nullifier.String(),
		})
	}

	return resp, nil
}

func getStatusVerificationResponse(verification models.VerificationResponse, vcs VerifiablePresentations) Status200JSONResponse {
	jwzMetadata := &JWZMetadata{
		UserDID: verification.UserDID,
	}
	if len(vcs) > 0 {
		jwzMetadata.VerifiablePresentations = vcs
	}

	if len(verification.Scopes) > 0 {
		nullifiers := make([]JWZProofs, 0, len(verification.Scopes))
		for _, scope := range verification.Scopes {
			nullifiers = append(nullifiers, JWZProofs{
				ScopeID:            scope.ID,
				NullifierSessionID: scope.NullifierSessionID,
				Nullifier:          scope.Nullifier,
			})
		}
		jwzMetadata.Nullifiers = &nullifiers
	}

	return Status200JSONResponse{
		Jwz:         common.ToPointer(verification.Jwz),
		JwzMetadata: jwzMetadata,
		Status:      statusSuccess,
	}
}
