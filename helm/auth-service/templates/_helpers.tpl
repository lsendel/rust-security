{{/*
Expand the name of the chart.
*/}}
{{- define "auth-service.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "auth-service.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "auth-service.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "auth-service.labels" -}}
helm.sh/chart: {{ include "auth-service.chart" . }}
{{ include "auth-service.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: rust-security-platform
{{- end }}

{{/*
Selector labels
*/}}
{{- define "auth-service.selectorLabels" -}}
app.kubernetes.io/name: {{ include "auth-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "auth-service.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "auth-service.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the container security context
*/}}
{{- define "auth-service.securityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop:
  - ALL
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65534
runAsGroup: 65534
seccompProfile:
  type: RuntimeDefault
{{- with .Values.securityContext }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Create the pod security context
*/}}
{{- define "auth-service.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65534
runAsGroup: 65534
fsGroup: 65534
seccompProfile:
  type: RuntimeDefault
{{- with .Values.podSecurityContext }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Create resource limits and requests
*/}}
{{- define "auth-service.resources" -}}
{{- if .Values.resources }}
{{- toYaml .Values.resources }}
{{- else }}
limits:
  cpu: 1000m
  memory: 512Mi
requests:
  cpu: 100m
  memory: 128Mi
{{- end }}
{{- end }}

{{/*
Create probe configuration
*/}}
{{- define "auth-service.livenessProbe" -}}
httpGet:
  path: {{ .Values.healthCheck.path | default "/health" }}
  port: http
initialDelaySeconds: {{ .Values.healthCheck.initialDelaySeconds | default 30 }}
periodSeconds: {{ .Values.healthCheck.periodSeconds | default 10 }}
timeoutSeconds: {{ .Values.healthCheck.timeoutSeconds | default 5 }}
failureThreshold: {{ .Values.healthCheck.failureThreshold | default 3 }}
successThreshold: 1
{{- end }}

{{- define "auth-service.readinessProbe" -}}
httpGet:
  path: {{ .Values.healthCheck.path | default "/health" }}
  port: http
initialDelaySeconds: 10
periodSeconds: 5
timeoutSeconds: {{ .Values.healthCheck.timeoutSeconds | default 5 }}
failureThreshold: 3
successThreshold: 1
{{- end }}

{{/*
Create environment variables for configuration
*/}}
{{- define "auth-service.envVars" -}}
- name: ENVIRONMENT
  value: {{ .Values.config.environment | quote }}
- name: RUST_LOG
  value: {{ .Values.config.logLevel | quote }}
- name: BIND_ADDR
  value: {{ .Values.config.bindAddr | quote }}
- name: TOKEN_EXPIRY_SECONDS
  value: {{ .Values.config.tokenExpirySeconds | quote }}
- name: RATE_LIMIT_REQUESTS_PER_MINUTE
  value: {{ .Values.config.rateLimitRequestsPerMinute | quote }}
- name: ALLOWED_ORIGINS
  value: {{ .Values.config.allowedOrigins | quote }}
{{- if .Values.config.jaegerEndpoint }}
- name: JAEGER_ENDPOINT
  value: {{ .Values.config.jaegerEndpoint | quote }}
{{- end }}
{{- if .Values.redis.enabled }}
- name: REDIS_URL
  value: "redis://{{ include "auth-service.fullname" . }}-redis-master:6379"
{{- end }}
{{- end }}

{{/*
Create secret environment variables
*/}}
{{- define "auth-service.secretEnvVars" -}}
- name: JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "auth-service.fullname" . }}-secret
      key: jwt-secret
- name: CLIENT_CREDENTIALS
  valueFrom:
    secretKeyRef:
      name: {{ include "auth-service.fullname" . }}-secret
      key: client-credentials
- name: REQUEST_SIGNING_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "auth-service.fullname" . }}-secret
      key: request-signing-secret
{{- if .Values.config.googleClientId }}
- name: GOOGLE_CLIENT_ID
  value: {{ .Values.config.googleClientId | quote }}
- name: GOOGLE_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "auth-service.fullname" . }}-secret
      key: google-client-secret
- name: GOOGLE_REDIRECT_URI
  value: {{ .Values.config.googleRedirectUri | quote }}
{{- end }}
{{- end }}