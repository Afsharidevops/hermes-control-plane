{{- define "hermes.name" -}}hermes-control-plane{{- end -}}
{{- define "hermes.fullname" -}}{{ .Release.Name }}{{- end -}}
{{- define "hermes.labels" -}}
app.kubernetes.io/name: {{ include "hermes.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end -}}
{{- define "hermes.secretName" -}}
{{- if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}{{- else -}}{{ include "hermes.fullname" . }}-secrets{{- end -}}
{{- end -}}
{{- define "hermes.secretValue" -}}
{{- $value := index . 0 -}}
{{- $fallback := index . 1 -}}
{{- if $value -}}{{ $value }}{{- else -}}{{ $fallback }}{{- end -}}
{{- end -}}
