package models

// JWZPayload is the struct that represents the payload of the message
type JWZPayload struct {
	Id   string `json:"id"`
	Typ  string `json:"typ"`
	Type string `json:"type"`
	Thid string `json:"thid"`
	Body struct {
		DidDoc struct {
			Context []string `json:"context"`
			Id      string   `json:"id"`
			Service []struct {
				Id              string `json:"id"`
				Type            string `json:"type"`
				ServiceEndpoint string `json:"serviceEndpoint"`
				Metadata        struct {
					Devices []struct {
						Ciphertext string `json:"ciphertext"`
						Alg        string `json:"alg"`
					} `json:"devices"`
				} `json:"metadata"`
			} `json:"service"`
		} `json:"did_doc"`
		Message interface{} `json:"message"`
		Scope   []struct {
			Proof struct {
				PiA      []string   `json:"pi_a"`
				PiB      [][]string `json:"pi_b"`
				PiC      []string   `json:"pi_c"`
				Protocol string     `json:"protocol"`
				Curve    string     `json:"curve"`
			} `json:"proof"`
			PubSignals []string `json:"pub_signals"`
			Id         int      `json:"id"`
			CircuitId  string   `json:"circuitId"`
			Vp         struct {
				Context              []string `json:"@context"`
				Type                 string   `json:"@type"`
				VerifiableCredential struct {
					Context           []string       `json:"@context"`
					Type              []string       `json:"@type"`
					CredentialSubject map[string]any `json:"credentialSubject"`
				} `json:"verifiableCredential"`
			} `json:"vp,omitempty"`
		} `json:"scope"`
	} `json:"body"`
	From string `json:"from"`
	To   string `json:"to"`
}
