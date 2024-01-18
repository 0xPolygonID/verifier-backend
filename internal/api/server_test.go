package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xPolygonID/verifier-backend/internal/common"
)

func TestSignIn(t *testing.T) {
	ctx := context.Background()
	server := New(cfg, keysLoader)

	type expected struct {
		httpCode int
		SignInResponseObject
	}

	type testConfig struct {
		name     string
		body     SignInRequestObject
		expected expected
	}

	for _, tc := range []testConfig{
		{
			name: "valid request for credentialAtomicQuerySigV2 circuit with KYCAgeCredential",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"allowedIssuers": ["*"],
						"type": "KYCAgeCredential",
						"credentialSubject": {
							"birthday": {
								"$eq": 19960424
							}
						}
					  }`),
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				SignInResponseObject: SignIn200JSONResponse{
					QrCode: QRCode{
						Body: Body{
							Scope: []Scope{
								{
									CircuitId: "credentialAtomicQuerySigV2",
									Id:        1,
									Query: map[string]interface{}{
										"allowedIssuers": []interface{}{"*"},
										"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
										"credentialSubject": map[string]interface{}{
											"birthday": map[string]interface{}{
												"$eq": float64(19960424),
											},
										},
										"type": "KYCAgeCredential",
									},
								},
							},
						},
						From: cfg.MumbaiSenderDID,
						To:   nil,
						Typ:  "application/iden3comm-plain-json",
						Type: "https://iden3-communication.io/authorization/1.0/request",
					},
				},
			},
		},
		{
			name: "valid request for credentialAtomicQuerySigV2 circuit with KYCAgeCredential and to field",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"allowedIssuers": ["*"],
						"type": "KYCAgeCredential",
						"credentialSubject": {
							"birthday": {
								"$eq": 19960424
							}
						}
					  }`),
					To: common.ToPointer("did:polygonid:polygon:mumbai:2qEATqfECVbCBzq9EhJpPSiv1xtJRpbMBKDaNM68Ci"),
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				SignInResponseObject: SignIn200JSONResponse{
					QrCode: QRCode{
						Body: Body{
							Scope: []Scope{
								{
									CircuitId: "credentialAtomicQuerySigV2",
									Id:        1,
									Query: map[string]interface{}{
										"allowedIssuers": []interface{}{"*"},
										"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
										"credentialSubject": map[string]interface{}{
											"birthday": map[string]interface{}{
												"$eq": float64(19960424),
											},
										},
										"type": "KYCAgeCredential",
									},
								},
							},
						},
						From: cfg.MumbaiSenderDID,
						To:   common.ToPointer("did:polygonid:polygon:mumbai:2qEATqfECVbCBzq9EhJpPSiv1xtJRpbMBKDaNM68Ci"),
						Typ:  "application/iden3comm-plain-json",
						Type: "https://iden3-communication.io/authorization/1.0/request",
					},
				},
			},
		},
		{
			name: "valid request for credentialAtomicQueryMTPV2 circuit with KYCAgeCredential",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQueryMTPV2",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"allowedIssuers": ["*"],
						"type": "KYCAgeCredential",
						"credentialSubject": {
							"birthday": {
								"$eq": 19960424
							}
						}
					  }`),
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				SignInResponseObject: SignIn200JSONResponse{
					QrCode: QRCode{
						Body: Body{
							Scope: []Scope{
								{
									CircuitId: "credentialAtomicQueryMTPV2",
									Id:        1,
									Query: map[string]interface{}{
										"allowedIssuers": []interface{}{"*"},
										"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
										"credentialSubject": map[string]interface{}{
											"birthday": map[string]interface{}{
												"$eq": float64(19960424),
											},
										},
										"type": "KYCAgeCredential",
									},
								},
							},
						},
						From: cfg.MumbaiSenderDID,
						To:   nil,
						Typ:  "application/iden3comm-plain-json",
						Type: "https://iden3-communication.io/authorization/1.0/request",
					},
				},
			},
		},
		{
			name: "valid request for credentialAtomicQueryV3-beta.0 circuit with KYCAgeCredential",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQueryMTPV2",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"allowedIssuers": ["*"],
						"type": "KYCAgeCredential",
						"credentialSubject": {
							"birthday": {
								"$eq": 19960424
							}
						},
						"proofType": "BJJSignature2021"
					  }`),
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				SignInResponseObject: SignIn200JSONResponse{
					QrCode: QRCode{
						Body: Body{
							Scope: []Scope{
								{
									CircuitId: "credentialAtomicQueryMTPV2",
									Id:        1,
									Query: map[string]interface{}{
										"allowedIssuers": []interface{}{"*"},
										"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
										"credentialSubject": map[string]interface{}{
											"birthday": map[string]interface{}{
												"$eq": float64(19960424),
											},
										},
										"type":      "KYCAgeCredential",
										"proofType": "BJJSignature2021",
									},
								},
							},
						},
						From: cfg.MumbaiSenderDID,
						To:   nil,
						Typ:  "application/iden3comm-plain-json",
						Type: "https://iden3-communication.io/authorization/1.0/request",
					},
				},
			},
		},
		{
			name: "invalid request - invalid ChainID",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("invalid"),
					CircuitID: "credentialAtomicQueryMTPV2",
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "field chainId value is wrong, got invalid, expected 80001 or 137",
					},
				},
			},
		},
		{
			name: "invalid request - invalid circuitID",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "invalid",
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "invalid circuitID",
					},
				},
			},
		},
		{
			name: "invalid request - invalid query - no context",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2",
					Query: jsonToMap(t, `{
						
					}`),
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "context cannot be empty",
					},
				},
			},
		},
		{
			name: "invalid request - invalid query - context empty",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2",
					Query: jsonToMap(t, `{
						"context": ""
					}`),
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "context cannot be empty",
					},
				},
			},
		},
		{
			name: "invalid request - invalid query - no type",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
					}`),
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "type cannot be empty",
					},
				},
			},
		},
		{
			name: "invalid request - invalid transaction data",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2OnChain",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"allowedIssuers": ["*"],
						"type": "KYCAgeCredential",
						"credentialSubject": {
							"birthday": {
								"$eq": 19960424
							}
						},
						"proofType": "BJJSignature2021"
					  }`),
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "field transactionData is empty",
					},
				},
			},
		},
		{
			name: "invalid request - invalid transaction data - empty contract",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					TransactionData: &TransactionData{
						ChainID:         1234,
						ContractAddress: "",
					},
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2OnChain",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"allowedIssuers": ["*"],
						"type": "KYCAgeCredential",
						"credentialSubject": {
							"birthday": {
								"$eq": 19960424
							}
						},
						"proofType": "BJJSignature2021"
					  }`),
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "field contractAddress is empty",
					},
				},
			},
		},
		{
			name: "valid on-chain request",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					TransactionData: &TransactionData{
						ChainID:         1234,
						ContractAddress: "0xE826f870852D7eeeB79B2C030298f9B5DAA8C8a3",
						MethodID:        "123",
						Network:         mumbaiNetwork,
					},
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2OnChain",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"allowedIssuers": ["*"],
						"type": "KYCAgeCredential",
						"credentialSubject": {
							"birthday": {
								"$eq": 19960424
							}
						},
						"proofType": "BJJSignature2021"
					  }`),
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				SignInResponseObject: SignIn200JSONResponse{
					QrCode: QRCode{
						Body: Body{
							Scope: []Scope{
								{
									CircuitId: "credentialAtomicQuerySigV2OnChain",
									Id:        1,
									Query: map[string]interface{}{
										"allowedIssuers": []interface{}{"*"},
										"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
										"credentialSubject": map[string]interface{}{
											"birthday": map[string]interface{}{
												"$eq": float64(19960424),
											},
										},
										"type":      "KYCAgeCredential",
										"proofType": "BJJSignature2021",
									},
								},
							},
						},
						From: cfg.MainSenderDID,
						To:   nil,
						Typ:  "application/iden3comm-plain-json",
						Type: "https://iden3-communication.io/proofs/1.0/contract-invoke-request",
					},
				},
			},
		},
		{
			name: "invalid request - invalid query onchain - empty type",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2OnChain",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"type": ""
					}`),
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "type cannot be empty",
					},
				},
			},
		},
		{
			name: "invalid request - invalid query - empty type",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"type": ""
					}`),
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "type cannot be empty",
					},
				},
			},
		},
		{
			name: "invalid request - invalid query - no allowedIssuers",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"type": "KYCAgeCredential"
					}`),
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "allowedIssuers cannot be empty",
					},
				},
			},
		},
		{
			name: "invalid request - invalid query - no credentialSubject",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID:   common.ToPointer("80001"),
					CircuitID: "credentialAtomicQuerySigV2",
					Query: jsonToMap(t, `{
						"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
						"type": "KYCAgeCredential",
						"allowedIssuers": ["*"]
					}`),
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
				SignInResponseObject: SignIn400JSONResponse{
					N400JSONResponse{
						Message: "credentialSubject cannot be empty",
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := server.SignIn(ctx, tc.body)
			require.NoError(t, err)
			switch tc.expected.httpCode {
			case http.StatusOK:
				response, ok := rr.(SignIn200JSONResponse)
				require.True(t, ok)
				expected, ok := tc.expected.SignInResponseObject.(SignIn200JSONResponse)
				require.True(t, ok)
				require.NotNil(t, expected.QrCode.Body.Scope)
				require.Len(t, expected.QrCode.Body.Scope, 1)
				require.Equal(t, expected.QrCode.Body.Scope, response.QrCode.Body.Scope)
				if expected.QrCode.Body.Scope[0].CircuitId == "credentialAtomicQuerySigV2" || expected.QrCode.Body.Scope[0].CircuitId == "credentialAtomicQueryMTPV2" || expected.QrCode.Body.Scope[0].CircuitId == "credentialAtomicQueryV3-beta.0" {
					require.NotNil(t, response.QrCode.Body.CallbackUrl)
					assert.True(t, isValidCallBack(t, *response.QrCode.Body.CallbackUrl))
				}
				assert.Equal(t, expected.QrCode.From, response.QrCode.From)
				assert.Equal(t, expected.QrCode.Typ, response.QrCode.Typ)
				assert.Equal(t, expected.QrCode.Type, response.QrCode.Type)
				assert.Equal(t, expected.QrCode.To, response.QrCode.To)

			case http.StatusBadRequest:
				response, ok := rr.(SignIn400JSONResponse)
				require.True(t, ok)
				expected, ok := tc.expected.SignInResponseObject.(SignIn400JSONResponse)
				require.True(t, ok)
				assert.Equal(t, expected.Message, response.Message)
			default:
				t.Errorf("unexpected http code: %d", tc.expected.httpCode)
			}
		})
	}
}

func TestQRStore(t *testing.T) {
	ctx := context.Background()
	server := New(cfg, keysLoader)

	type expected struct {
		httpCode int
		QRStoreResponseObject
	}

	type testConfig struct {
		name     string
		body     QRStoreRequestObject
		expected expected
	}

	for _, tc := range []testConfig{
		{
			name: "valid request",
			body: QRStoreRequestObject{
				Body: &QRStoreJSONRequestBody{
					From: "did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
					To:   common.ToPointer(""),
					Typ:  "application/iden3comm-plain-json",
					Type: "https://iden3-communication.io/authorization/1.0/request",
					Thid: "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Id:   "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Body: Body{
						CallbackUrl: common.ToPointer("http://localhost:3000/callback?n=1"),
						Reason:      "reason",
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQuerySigV2",
								Id:        1,
								Query:     map[string]interface{}{},
							},
						},
					},
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
			},
		},
		{
			name: "invalid request missing from field",
			body: QRStoreRequestObject{
				Body: &QRStoreJSONRequestBody{
					From: "",
					To:   common.ToPointer(""),
					Typ:  "application/iden3comm-plain-json",
					Type: "https://iden3-communication.io/authorization/1.0/request",
					Thid: "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Id:   "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Body: Body{
						CallbackUrl: common.ToPointer("http://localhost:3000/callback?n=1"),
						Reason:      "reason",
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQuerySigV2",
								Id:        1,
								Query:     map[string]interface{}{},
							},
						},
					},
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
			},
		},
		{
			name: "invalid request missing type field",
			body: QRStoreRequestObject{
				Body: &QRStoreJSONRequestBody{
					From: "did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
					To:   common.ToPointer(""),
					Typ:  "application/iden3comm-plain-json",
					Type: "",
					Thid: "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Id:   "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Body: Body{
						CallbackUrl: common.ToPointer("http://localhost:3000/callback?n=1"),
						Reason:      "reason",
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQuerySigV2",
								Id:        1,
								Query:     map[string]interface{}{},
							},
						},
					},
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
			},
		},
		{
			name: "invalid request missing thid field",
			body: QRStoreRequestObject{
				Body: &QRStoreJSONRequestBody{
					From: "did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
					To:   common.ToPointer(""),
					Typ:  "application/iden3comm-plain-json",
					Type: "https://iden3-communication.io/authorization/1.0/request",
					Thid: "",
					Id:   "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Body: Body{
						CallbackUrl: common.ToPointer("http://localhost:3000/callback?n=1"),
						Reason:      "reason",
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQuerySigV2",
								Id:        1,
								Query:     map[string]interface{}{},
							},
						},
					},
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
			},
		},
		{
			name: "invalid request missing id field",
			body: QRStoreRequestObject{
				Body: &QRStoreJSONRequestBody{
					From: "did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
					To:   common.ToPointer(""),
					Typ:  "application/iden3comm-plain-json",
					Type: "https://iden3-communication.io/authorization/1.0/request",
					Thid: "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Id:   "",
					Body: Body{
						CallbackUrl: common.ToPointer("http://localhost:3000/callback?n=1"),
						Reason:      "reason",
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQuerySigV2",
								Id:        1,
								Query:     map[string]interface{}{},
							},
						},
					},
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
			},
		},
		{
			name: "invalid request missing body field",
			body: QRStoreRequestObject{
				Body: &QRStoreJSONRequestBody{
					From: "did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
					To:   common.ToPointer(""),
					Typ:  "application/iden3comm-plain-json",
					Type: "https://iden3-communication.io/authorization/1.0/request",
					Thid: "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Id:   "7f38a193-0918-4a48-9fac-36adfdb8b542",
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
			},
		},
		{
			name: "invalid request missing body field 2",
			body: QRStoreRequestObject{
				Body: &QRStoreJSONRequestBody{
					From: "did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
					To:   common.ToPointer(""),
					Typ:  "application/iden3comm-plain-json",
					Type: "https://iden3-communication.io/authorization/1.0/request",
					Thid: "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Id:   "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Body: Body{},
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
			},
		},
		{
			name: "invalid request missing scope field",
			body: QRStoreRequestObject{
				Body: &QRStoreJSONRequestBody{
					From: "did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
					To:   common.ToPointer(""),
					Typ:  "application/iden3comm-plain-json",
					Type: "https://iden3-communication.io/authorization/1.0/request",
					Thid: "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Id:   "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Body: Body{
						CallbackUrl: common.ToPointer("http://localhost:3000/callback?n=1"),
						Reason:      "reason",
					},
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
			},
		},
		{
			name: "invalid request missing reason field",
			body: QRStoreRequestObject{
				Body: &QRStoreJSONRequestBody{
					From: "did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT",
					To:   common.ToPointer(""),
					Typ:  "application/iden3comm-plain-json",
					Type: "https://iden3-communication.io/authorization/1.0/request",
					Thid: "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Id:   "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Body: Body{
						CallbackUrl: common.ToPointer("http://localhost:3000/callback?n=1"),
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQuerySigV2",
								Id:        1,
								Query:     map[string]interface{}{},
							},
						},
					},
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
			},
		},
		{
			name: "invalid request missing typ field",
			body: QRStoreRequestObject{
				Body: &QRStoreJSONRequestBody{
					From: "",
					To:   common.ToPointer(""),
					Typ:  "application/iden3comm-plain-json",
					Type: "https://iden3-communication.io/authorization/1.0/request",
					Thid: "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Id:   "7f38a193-0918-4a48-9fac-36adfdb8b542",
					Body: Body{
						CallbackUrl: common.ToPointer("http://localhost:3000/callback?n=1"),
						Reason:      "reason",
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQuerySigV2",
								Id:        1,
								Query:     map[string]interface{}{},
							},
						},
					},
				},
			},
			expected: expected{
				httpCode: http.StatusBadRequest,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := server.QRStore(ctx, tc.body)
			require.NoError(t, err)
			switch tc.expected.httpCode {
			case http.StatusOK:
				response, ok := rr.(QRStore200JSONResponse)
				require.True(t, ok)
				assert.True(t, isValidaQrStoreCallback(t, string(response)))
			case http.StatusBadRequest:
				_, ok := rr.(QRStore400JSONResponse)
				require.True(t, ok)
			default:
				t.Errorf("unexpected http code: %d", tc.expected.httpCode)
			}
		})
	}
}

func isValidaQrStoreCallback(t *testing.T, url string) bool {
	callBackURL := url
	items := strings.Split(callBackURL, "/qr-store?")
	if len(items) != 2 {
		return false
	}
	if items[0] != "iden3comm://?request_uri="+cfg.Host {
		return false
	}

	queryItems := strings.Split(items[1], "=")
	if len(queryItems) != 2 {
		return false
	}

	_, err := uuid.Parse(queryItems[1])
	require.NoError(t, err)
	return true
}

func isValidCallBack(t *testing.T, url string) bool {
	callBackURL := url
	items := strings.Split(callBackURL, "?")
	if len(items) != 2 {
		return false
	}
	if items[0] != cfg.Host+"/callback" {
		return false
	}

	queryItems := strings.Split(items[1], "=")
	if len(queryItems) != 2 {
		return false
	}

	_, err := uuid.Parse(queryItems[1])
	require.NoError(t, err)
	return true
}
