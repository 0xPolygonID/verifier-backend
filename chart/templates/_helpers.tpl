{{- define "verifier-backend.fullname" -}}
{{- .Release.Name }}
{{- end }}

{{- define "verifier-backend.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "verifier-backend.allLabels" -}}
{{ include "verifier-backend.labels" . }}
app.kubernetes.io/name: {{ include "verifier-backend.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "verifier-backend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "verifier-backend.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
