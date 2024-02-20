# Verifier Backend
[![Checks](https://github.com/0xPolygonID/verifier-backend/actions/workflows/checks.yml/badge.svg)](https://github.com/0xPolygonID/verifier-backend/actions/workflows/checks.yml)
[![golangci-lint](https://github.com/0xPolygonID/verifier-backend/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/0xPolygonID/verifier-backend/actions/workflows/golangci-lint.yml)

### Requirements:
1. Create a file named `.env` in the root directory of the project. .env-example is provided as an example.
2. Create a file named `resolvers_settings.yaml` in the root directory of the project. resolvers_settings_sample.yaml is provided as an example.

### Some useful commands:

```shell
make run      # run the server
make stop     # stop the server
make restart  # stop and remove the container, build the image and run the container
```

### Cache expiration
The default cache expiration is 1 hour. This can be changed by setting the environment variable `VERIFIER_BACKEND_CACHE_EXPIRATION` to the desired value.
For instance, to set the cache expiration to 30 minutes, you can run the following command:
```shell
VERIFIER_BACKEND_CACHE_EXPIRATION=30m
```


#### sign-in body example - credentialAtomicQuerySigV2:

```json
{
  "chainID": "80001",
  "skipClaimRevocationCheck": false,
  "scope" : [
    {
      "ID": 1,
      "circuitID": "credentialAtomicQuerySigV2",
      "query": {
        "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
        "allowedIssuers": ["*"],
        "type": "KYCAgeCredential",
        "credentialSubject": {
          "birthday": {
            "$eq": 19960424
          }
        }
      }
    }
  ]
}
```

#### sign-in payload response sample:

```json
{
  "qrCode": "iden3comm://?request_uri=https://verifier-backend.polygonid.me/qr-store?id=99f79449-cbe4-4c55-9532-3a4344c7fb9c",
  "sessionID": "c9d8cebf-21cd-4c21-8232-a6ad6ee6a168"
}
```

### More Samples

#### sign-in body example - credentialAtomicQueryMTPV2:

```json
{
  "chainID": "80001",
  "skipClaimRevocationCheck": false,
  "scope" : [
    {
      "ID": 1,
      "circuitID": "credentialAtomicQueryMTPV2",
      "query": {
        "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
        "allowedIssuers": ["*"],
        "type": "KYCAgeCredential",
        "credentialSubject": {
          "birthday": {
            "$eq": 19960424
          }
        }
      }
    }
  ]
}
```

> Note: `credentialAtomicQueryV3-beta.0` is the same circuit for BJJSignature2021 and Iden3SparseMerkleTreeProof. 
> You must specify the proofType in the query. 

#### sign-in body example - credentialAtomicQueryV3-beta.0 - BJJSignature2021:

```json
{
  "chainID": "80001",
  "skipClaimRevocationCheck": false,
  "scope" : [
    {
      "Id": 1,
      "circuitID": "credentialAtomicQueryV3-beta.0",
      "query": {
        "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
        "allowedIssuers": ["*"],
        "type": "KYCAgeCredential",
        "credentialSubject": {
          "birthday": {
            "$eq": 19960424
          }
        },
        "proofType": "BJJSignature2021"
      }
    }
  ]
}
```

#### sign-in body example - credentialAtomicQueryV3-beta.0 - Iden3SparseMerkleTreeProof:

```json
{
  "chainID": "80001",
  "skipClaimRevocationCheck": false,
  "scope" : [
    {
      "Id": 1,
      "circuitID": "credentialAtomicQueryV3-beta.0",
      "query": {
        "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
        "allowedIssuers": ["*"],
        "type": "KYCAgeCredential",
        "credentialSubject": {
          "birthday": {
            "$eq": 19960424
          }
        },
        "proofType": "Iden3SparseMerkleTreeProof"
      }
    }
  ]
}
```

#### Multi-Query Example
```json
{
  "chainID": "80001",
  "skipClaimRevocationCheck": false,
  "scope": [
    {
      "id" : 1,
      "circuitID": "credentialAtomicQueryV3-beta.0",
      "query" : {
        "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
        "allowedIssuers": ["*"],
        "type": "KYCAgeCredential",
        "credentialSubject": {
          "birthday": {
            "$eq": 19960424
          }
        },
        "proofType": "BJJSignature2021" // Iden3SparseMerkleTreeProof or BJJSignature2021
      }
    },
    {
      "id" : 2,
      "circuitID": "credentialAtomicQueryV3-beta.0",
      "query" : {
        "context": "ipfs://QmaBJzpoYT2CViDx5ShJiuYLKXizrPEfXo8JqzrXCvG6oc",
        "allowedIssuers": ["*"],
        "type": "TestInteger01",
        "credentialSubject": {
          "position": {
            "$eq": 1
          }
        },
        "proofType": "BJJSignature2021" // Iden3SparseMerkleTreeProof or BJJSignature2021
      }
    }
  ]
}
```

#### OnChain BJJSignature2021 credentialAtomicQueryV3OnChain-beta.0
```json
{
  "reason": "test flow",
  "to": null,
  "scope" : [
      {
        "id": 3,
        "circuitID": "credentialAtomicQueryV3OnChain-beta.0",
        "query" : {
            "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
            "allowedIssuers": ["*"],
            "type": "KYCAgeCredential",
            "credentialSubject": {
                "birthday": {
                    
                }
            },
            "proofType": "BJJSignature2021"
        }
      }
  ],
  "transactionData": {
    "contractAddress": "0xD0Fd3E9fDF448e5B86Cc0f73E5Ee7D2F284884c0",
    "methodID": "b68967e2",
    "chainID": 80001,
    "network": "polygon-mumbai"
  }
}
```
