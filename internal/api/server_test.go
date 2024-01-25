package api

import (
	"context"
	"math/big"
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
		httpCode     int
		QRCode       QRCode
		ErrorMessage string
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
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							CircuitId: "credentialAtomicQuerySigV2",
							Id:        1,
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
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				QRCode: QRCode{
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
		{
			name: "valid request for credentialAtomicQuerySigV2 circuit with KYCAgeCredential and to field",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQuerySigV2",
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
					To: common.ToPointer("did:polygonid:polygon:mumbai:2qEATqfECVbCBzq9EhJpPSiv1xtJRpbMBKDaNM68Ci"),
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				QRCode: QRCode{
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
		{
			name: "valid request for credentialAtomicQueryMTPV2 circuit with KYCAgeCredential",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQueryMTPV2",
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
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				QRCode: QRCode{
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
		{
			name: "valid request for credentialAtomicQueryV3-beta.0 circuit with KYCAgeCredential",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQueryV3-beta.0",
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
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				QRCode: QRCode{
					Body: Body{
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQueryV3-beta.0",
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
		{
			name: "valid request for credentialAtomicQueryV3-beta.0 circuit with KYCAgeCredential and nullifierSessionId",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQueryV3-beta.0",
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
							Params: common.ToPointer(map[string]interface{}{
								"nullifierSessionID": big.NewInt(100).String(),
							}),
						},
					},
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				QRCode: QRCode{
					Body: Body{
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQueryV3-beta.0",
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
								Params: common.ToPointer(map[string]interface{}{
									"nullifierSessionId": big.NewInt(100).String(),
								}),
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
		{
			name: "invalid request duplicated query id",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQueryV3-beta.0",
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
						{
							CircuitId: "credentialAtomicQueryV3-beta.0",
							Id:        1,
							Query: jsonToMap(t, `{
							"context": "ipfs://QmaBJzpoYT2CViDx5ShJiuYLKXizrPEfXo8JqzrXCvG6oc",
							"allowedIssuers": ["*"],
							"type": "TestInteger01",
							"credentialSubject": {
								"position": {
									"$eq": 1
								}
							},
							"proofType": "BJJSignature2021"
						  }`),
						},
					},
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "field scope id must be unique, got 1 multiple times",
			},
		},
		{
			name: "valid request for credentialAtomicQueryV3-beta.0 and TestInteger01 circuits",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQueryV3-beta.0",
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
						{
							CircuitId: "credentialAtomicQueryV3-beta.0",
							Id:        2,
							Query: jsonToMap(t, `{
							"context": "ipfs://QmaBJzpoYT2CViDx5ShJiuYLKXizrPEfXo8JqzrXCvG6oc",
							"allowedIssuers": ["*"],
							"type": "TestInteger01",
							"credentialSubject": {
								"position": {
									"$eq": 1
								}
							},
							"proofType": "BJJSignature2021"
						  }`),
						},
					},
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				QRCode: QRCode{
					Body: Body{
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQueryV3-beta.0",
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
							{
								CircuitId: "credentialAtomicQueryV3-beta.0",
								Id:        2,
								Query: map[string]interface{}{
									"allowedIssuers": []interface{}{"*"},
									"context":        "ipfs://QmaBJzpoYT2CViDx5ShJiuYLKXizrPEfXo8JqzrXCvG6oc",
									"credentialSubject": map[string]interface{}{
										"position": map[string]interface{}{
											"$eq": float64(1),
										},
									},
									"type":      "TestInteger01",
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
		{
			name: "valid request for credentialAtomicQueryV3OnChain-beta.0 circuit",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        3,
							CircuitId: "credentialAtomicQueryV3OnChain-beta.0",
							Query: jsonToMap(t, `{
							"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
							"allowedIssuers": ["*"],
							"type": "KYCAgeCredential",
							"credentialSubject": {
								"birthday": {
									
								}
							},
							"proofType": "BJJSignature2021"
						  }`),
						},
					},
					TransactionData: &TransactionData{
						ContractAddress: "0xD0Fd3E9fDF448e5B86Cc0f73E5Ee7D2F284884c0",
						MethodID:        "b68967e2",
						ChainID:         80001,
						Network:         mumbaiNetwork,
					},
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				QRCode: QRCode{
					Body: Body{
						Scope: []Scope{
							{
								CircuitId: "credentialAtomicQueryV3OnChain-beta.0",
								Id:        3,
								Query: map[string]interface{}{
									"allowedIssuers": []interface{}{"*"},
									"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
									"credentialSubject": map[string]interface{}{
										"birthday": map[string]interface{}{},
									},
									"type":      "KYCAgeCredential",
									"proofType": "BJJSignature2021",
								},
							},
						},
						TransactionData: &TransactionDataResponse{
							ContractAddress: "0xD0Fd3E9fDF448e5B86Cc0f73E5Ee7D2F284884c0",
							MethodId:        "b68967e2",
							ChainId:         80001,
							Network:         mumbaiNetwork,
						},
					},
					From: cfg.MumbaiSenderDID,
					To:   nil,
					Typ:  "application/iden3comm-plain-json",
					Type: "https://iden3-communication.io/proofs/1.0/contract-invoke-request",
				},
			},
		},
		{
			name: "invalid request for credentialAtomicQueryV3-beta.0 and KYCAgeCredential circuits",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQueryV3-beta.0",
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
						{
							CircuitId: "credentialAtomicQuerySigV2OnChain",
							Id:        2,
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
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "field circuitId value is wrong, got credentialAtomicQuerySigV2OnChain, expected credentialAtomicQuerySigV2 or credentialAtomicQueryMTPV2 or credentialAtomicQueryV3-beta.0",
			},
		},
		{
			name: "invalid request for credentialAtomicQueryV3-beta.0 and credentialAtomicQuerySigV2OnChain circuits",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQuerySigV2OnChain",
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
						{
							CircuitId: "credentialAtomicQueryV3-beta.0",
							Id:        2,
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
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "field circuitId value is wrong, got credentialAtomicQueryV3-beta.0, expected credentialAtomicQuerySigV2OnChain or credentialAtomicQueryMTPV2OnChain or credentialAtomicQueryV3OnChain-beta.0",
			},
		},
		{
			name: "invalid request - invalid params",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQueryV3-beta.0",
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
							Params: common.ToPointer(map[string]interface{}{
								"nullifierSessionID": "invalid",
							}),
						},
					},
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "nullifierSessionID is not a valid big integer",
			},
		},
		{
			name: "invalid request - invalid ChainID",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("invalid"),
					Scope: []ScopeRequest{
						{
							CircuitId: "credentialAtomicQueryV3-beta.0",
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
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "field chainId value is wrong, got invalid, expected 80001 or 137",
			},
		},
		{
			name: "invalid request - invalid circuitID",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							CircuitId: "credentialAtomicQueryV3-beta.1111",
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
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "invalid circuitID",
			},
		},
		{
			name: "invalid request - invalid query - no context",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQueryV3-beta.0",
							Query: jsonToMap(t, `{
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
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "context cannot be empty",
			},
		},
		{
			name: "invalid request - invalid query - context empty",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQueryV3-beta.0",
							Query: jsonToMap(t, `{
							"context": "",
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
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "context cannot be empty",
			},
		},
		{
			name: "invalid request - invalid query - no type",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQueryV3-beta.0",
							Query: jsonToMap(t, `{
							"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
							"allowedIssuers": ["*"],
							"credentialSubject": {
								"birthday": {
									"$eq": 19960424
								}
							},
							"proofType": "BJJSignature2021"
						  }`),
						},
					},
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "type cannot be empty",
			},
		},
		{
			name: "invalid request - invalid transaction data",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQuerySigV2OnChain",
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
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "field transactionData is empty",
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
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQuerySigV2OnChain",
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
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "field contractAddress is empty",
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
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQuerySigV2OnChain",
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
				},
			},
			expected: expected{
				httpCode: http.StatusOK,
				QRCode: QRCode{
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
		{
			name: "invalid request - invalid query onchain - empty type",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQuerySigV2OnChain",
							Query: jsonToMap(t, `{
							"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
							"allowedIssuers": ["*"],
							"type": "",
							"credentialSubject": {
								"birthday": {
									"$eq": 19960424
								}
							},
							"proofType": "BJJSignature2021"
						  }`),
						},
					},
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "type cannot be empty",
			},
		},
		{
			name: "invalid request - invalid query - empty type",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQuerySigV2",
							Query: jsonToMap(t, `{
							"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
							"allowedIssuers": ["*"],
							"type": "",
							"credentialSubject": {
								"birthday": {
									"$eq": 19960424
								}
							},
							"proofType": "BJJSignature2021"
						  }`),
						},
					},
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "type cannot be empty",
			},
		},
		{
			name: "invalid request - invalid query - no allowedIssuers",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQuerySigV2",
							Query: jsonToMap(t, `{
							"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
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
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "allowedIssuers cannot be empty",
			},
		},
		{
			name: "invalid request - invalid query - no credentialSubject",
			body: SignInRequestObject{
				Body: &SignInJSONRequestBody{
					ChainID: common.ToPointer("80001"),
					Scope: []ScopeRequest{
						{
							Id:        1,
							CircuitId: "credentialAtomicQuerySigV2",
							Query: jsonToMap(t, `{
							"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
							"allowedIssuers": ["*"],
							"type": "KYCAgeCredential",
							"proofType": "BJJSignature2021"
						  }`),
						},
					},
				},
			},
			expected: expected{
				httpCode:     http.StatusBadRequest,
				ErrorMessage: "credentialSubject cannot be empty",
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
				expected := tc.expected.QRCode
				require.NotNil(t, expected.Body.Scope)

				id := isValidaQrStoreCallback(t, response.QrCode)

				rr2, err := server.GetQRCodeFromStore(ctx,
					GetQRCodeFromStoreRequestObject{
						Params: GetQRCodeFromStoreParams{Id: id},
					})
				require.NoError(t, err)
				got, ok := rr2.(GetQRCodeFromStore200JSONResponse)
				require.True(t, ok)

				require.Len(t, expected.Body.Scope, len(got.Body.Scope))
				require.Equal(t, expected.Body.Scope, got.Body.Scope)

				if expected.Body.Scope[0].CircuitId == "credentialAtomicQuerySigV2" ||
					expected.Body.Scope[0].CircuitId == "credentialAtomicQueryMTPV2" ||
					expected.Body.Scope[0].CircuitId == "credentialAtomicQueryV3-beta.0" {
					require.NotNil(t, got.Body.CallbackUrl)
					assert.True(t, isValidCallBack(t, *got.Body.CallbackUrl))
					if expected.Body.Scope[0].Params != nil {
						assert.Equal(t, expected.Body.Scope[0].Params, got.Body.Scope[0].Params)
					}
				}
				assert.Equal(t, expected.From, got.From)
				assert.Equal(t, expected.Typ, got.Typ)
				assert.Equal(t, expected.Type, got.Type)
				assert.Equal(t, expected.To, got.To)

				if expected.Body.TransactionData != nil {
					assert.Equal(t, expected.Body.TransactionData.ChainId, got.Body.TransactionData.ChainId)
					assert.Equal(t, expected.Body.TransactionData.ContractAddress, got.Body.TransactionData.ContractAddress)
					assert.Equal(t, expected.Body.TransactionData.MethodId, got.Body.TransactionData.MethodId)
					assert.Equal(t, expected.Body.TransactionData.Network, got.Body.TransactionData.Network)
				}

			case http.StatusBadRequest:
				response, ok := rr.(SignIn400JSONResponse)
				require.True(t, ok)
				assert.Equal(t, tc.expected.ErrorMessage, response.Message)
			default:
				t.Errorf("unexpected http code: %d", tc.expected.httpCode)
			}
		})
	}
}

func isValidaQrStoreCallback(t *testing.T, url string) uuid.UUID {
	t.Helper()
	callBackURL := url
	items := strings.Split(callBackURL, "/qr-store?")
	require.Len(t, items, 2)

	require.Equal(t, "iden3comm://?request_uri="+cfg.Host, items[0])

	queryItems := strings.Split(items[1], "=")
	require.Len(t, queryItems, 2)

	id, err := uuid.Parse(queryItems[1])
	require.NoError(t, err)

	return id
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
