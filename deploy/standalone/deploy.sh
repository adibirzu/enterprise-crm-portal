#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Enterprise CRM Portal — Standalone OKE Deployment
#
# Deploys the CRM portal to any OCI tenancy with Oracle ATP.
#
# Prerequisites:
#   - kubectl configured for your OKE cluster
#   - Oracle ATP provisioned with a wallet downloaded
#     (use deploy/oci/ensure_atp.sh to create one if needed)
#   - Python 3 (secret files and build metadata)
#   - Docker with Buildx and OCIR login for builds (or use a pre-built image)
#
# Optional post-deploy:
#   deploy/oci/ensure_db_observability.sh — enables DB Management + OPSI
#
# Required env vars:
#   DNS_DOMAIN          — your DNS domain (e.g., <your-domain>)
#   ORACLE_DSN          — ATP TNS name (e.g., myatp_low)
#   ORACLE_PASSWORD     — ATP admin password
#   ORACLE_WALLET_DIR   — local path to unzipped wallet
#   ORACLE_WALLET_PASSWORD — wallet password
#   OCIR_REGION         — OCI region for building (e.g., <region-key>)
#   OCIR_TENANCY        — OCIR tenancy namespace for building
#
# Optional env vars:
#   IDCS_DOMAIN_URL, IDCS_CLIENT_ID, IDCS_CLIENT_SECRET — enables SSO
#   OCI_APM_ENDPOINT, OCI_APM_PRIVATE_DATAKEY — enables OTel/APM
#   OCTO_DRONE_SHOP_URL — enables order sync integration
#   INTERNAL_SERVICE_KEY — enables simulation proxy (must match the shop)
#   NAMESPACE           — k8s namespace (default: enterprise-crm)
#   IMAGE_TAG           — push tag (default: timestamp)
#   IMAGE_PLATFORM      — Linux target platform (required on non-amd64 hosts)
#   SKIP_BUILD          — set to true to deploy an existing image
#   IMAGE_REF           — existing registry/repository@sha256:<digest> when skipping build
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

_require() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        echo "ERROR: $name is required but not set." >&2
        exit 1
    fi
}

_resolve_secret() {
    local name="$1"
    local file_var="${name}_FILE"
    local current="${!name:-}"
    if [[ -n "$current" ]]; then
        return
    fi
    local file_path="${!file_var:-}"
    if [[ -n "$file_path" ]]; then
        export "$name"="$(python3 - "$file_path" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).read_text(encoding="utf-8").strip())
PY
)"
    fi
}

_generate_secret() {
    openssl rand -hex 32 2>/dev/null || python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
}

_build_image_digest() (
    local metadata_dir
    metadata_dir="$(mktemp -d)" || exit 1
    trap 'rm -rf -- "$metadata_dir"' EXIT

    echo "[standalone] Building and pushing ${IMAGE}:${IMAGE_TAG} for ${IMAGE_PLATFORM}..." >&2
    docker buildx build --platform "$IMAGE_PLATFORM" --tag "${IMAGE}:${IMAGE_TAG}" \
        --build-arg "SOURCE_COMMIT=${SOURCE_COMMIT}" \
        --push --metadata-file "$metadata_dir/image.json" "$PROJECT_ROOT" >&2 || exit 1
    python3 - "$metadata_dir/image.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as metadata:
    digest = json.load(metadata).get("containerimage.digest")
if isinstance(digest, str):
    sys.stdout.write(digest)
PY
)

_resolve_secret ORACLE_PASSWORD
_resolve_secret ORACLE_WALLET_PASSWORD
_resolve_secret APP_SECRET_KEY
_resolve_secret INTERNAL_SERVICE_KEY
_resolve_secret IDCS_CLIENT_SECRET
_resolve_secret SPLUNK_HEC_TOKEN
_resolve_secret OCI_APM_PRIVATE_DATAKEY
_resolve_secret OCI_APM_PUBLIC_DATAKEY
_resolve_secret OCI_APM_RUM_PUBLIC_DATAKEY

# ── Validate required inputs ──────────────────────────────────────
_require DNS_DOMAIN
_require ORACLE_DSN
_require ORACLE_PASSWORD
_require ORACLE_WALLET_DIR
_require ORACLE_WALLET_PASSWORD

repository_pattern='[a-z0-9]+(-[a-z0-9]+)*([.][a-z0-9]+(-[a-z0-9]+)*)+(:[0-9]+)?(/[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*)+'
digest_pattern='sha256:[a-f0-9]{64}'
if [[ "${SKIP_BUILD:-}" == "true" ]]; then
    if [[ ! "${IMAGE_REF:-}" =~ ^${repository_pattern}@${digest_pattern}$ ]]; then
        echo "ERROR: IMAGE_REF must be registry/repository@sha256:<64 lowercase hex digits> when SKIP_BUILD=true." >&2
        exit 1
    fi
    IMAGE_SOURCE="$IMAGE_REF"
else
    if [[ -n "${IMAGE_REF:-}" ]]; then
        echo "ERROR: Set SKIP_BUILD=true to deploy the supplied IMAGE_REF." >&2
        exit 1
    fi
    _require OCIR_REGION
    _require OCIR_TENANCY
    IMAGE="${OCIR_REGION}.ocir.io/${OCIR_TENANCY}/enterprise-crm-portal"
    if [[ ! "$IMAGE" =~ ^${repository_pattern}$ ]]; then
        echo "ERROR: OCIR_REGION and OCIR_TENANCY must form a valid image repository." >&2
        exit 1
    fi
    IMAGE_TAG="${IMAGE_TAG:-$(date +%Y%m%d%H%M%S)}"
    if [[ ! "$IMAGE_TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ || "$IMAGE_TAG" == "latest" ]]; then
        echo "ERROR: IMAGE_TAG must be a valid push tag other than latest." >&2
        exit 1
    fi
    if [[ -z "${IMAGE_PLATFORM:-}" ]]; then
        case "$(uname -m)" in
            amd64|x86_64) IMAGE_PLATFORM=linux/amd64 ;;
            *)
                echo "ERROR: IMAGE_PLATFORM is required to build on a non-amd64 host." >&2
                exit 1
                ;;
        esac
    fi
    if [[ ! "$IMAGE_PLATFORM" =~ ^linux/[a-z0-9]+(/[a-z0-9]+)?$ ]]; then
        echo "ERROR: IMAGE_PLATFORM must be an explicit Linux target such as linux/amd64." >&2
        exit 1
    fi
    IMAGE_SOURCE="${IMAGE}:${IMAGE_TAG}"
fi

NAMESPACE="${NAMESPACE:-enterprise-crm}"
ORACLE_USER="${ORACLE_USER:-ADMIN}"
CRM_URL="https://crm.${DNS_DOMAIN}"
APP_SECRET_KEY="${APP_SECRET_KEY:-$(_generate_secret)}"

if [[ -n "${OCTO_DRONE_SHOP_URL:-}" && -z "${INTERNAL_SERVICE_KEY:-}" ]]; then
    echo "ERROR: INTERNAL_SERVICE_KEY (or INTERNAL_SERVICE_KEY_FILE) is required when OCTO_DRONE_SHOP_URL is set." >&2
    exit 1
fi

# Auto-derive IDCS redirect URI
IDCS_REDIRECT_URI="${IDCS_REDIRECT_URI:-${CRM_URL}/api/auth/sso/callback}"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Enterprise CRM Portal — Standalone Deploy                      ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  Domain:    ${DNS_DOMAIN}"
echo "║  CRM URL:   ${CRM_URL}"
echo "║  Image:     ${IMAGE_SOURCE}"
echo "║  Namespace: ${NAMESPACE}"
echo "║  ATP DSN:   ${ORACLE_DSN}"
echo "║  SSO:       ${IDCS_DOMAIN_URL:+enabled}${IDCS_DOMAIN_URL:-disabled (local auth only)}"
echo "║  APM:       ${OCI_APM_ENDPOINT:+enabled}${OCI_APM_ENDPOINT:-disabled}"
echo "║  Shop URL:  ${OCTO_DRONE_SHOP_URL:-not configured}"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Resolve the pushed manifest digest before changing any Kubernetes resources.
if [[ "${SKIP_BUILD:-}" != "true" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROJECT_ROOT="${SCRIPT_DIR}/../.."
    SOURCE_COMMIT="${SOURCE_COMMIT:-$(git -C "$PROJECT_ROOT" rev-parse --verify HEAD 2>/dev/null || true)}"
    if [[ ! "$SOURCE_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]]; then
        echo "ERROR: SOURCE_COMMIT must resolve to a 40-hex commit." >&2
        exit 1
    fi
    if ! image_digest="$(_build_image_digest)" || [[ ! "$image_digest" =~ ^${digest_pattern}$ ]]; then
        echo "ERROR: Buildx did not return a valid pushed image digest." >&2
        exit 1
    fi
    IMAGE_REF="${IMAGE}@${image_digest}"
fi

# ── Create namespace ──────────────────────────────────────────────
kubectl create namespace "$NAMESPACE" 2>/dev/null || true

# ── Create wallet secret ──────────────────────────────────────────
echo "[standalone] Creating wallet secret..."
kubectl create secret generic crm-wallet \
    --from-file="${ORACLE_WALLET_DIR}" \
    --namespace="$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -

# ── Create secrets ────────────────────────────────────────────────
echo "[standalone] Creating secrets..."
kubectl create secret generic crm-secrets \
    --namespace="$NAMESPACE" \
    --from-literal="ORACLE_PASSWORD=${ORACLE_PASSWORD}" \
    --from-literal="ORACLE_WALLET_PASSWORD=${ORACLE_WALLET_PASSWORD}" \
    --from-literal="APP_SECRET_KEY=${APP_SECRET_KEY}" \
    ${INTERNAL_SERVICE_KEY:+--from-literal="INTERNAL_SERVICE_KEY=${INTERNAL_SERVICE_KEY}"} \
    ${IDCS_CLIENT_SECRET:+--from-literal="IDCS_CLIENT_SECRET=${IDCS_CLIENT_SECRET}"} \
    ${SPLUNK_HEC_TOKEN:+--from-literal="SPLUNK_HEC_TOKEN=${SPLUNK_HEC_TOKEN}"} \
    ${OCI_APM_PRIVATE_DATAKEY:+--from-literal="OCI_APM_PRIVATE_DATAKEY=${OCI_APM_PRIVATE_DATAKEY}"} \
    ${OCI_APM_PUBLIC_DATAKEY:+--from-literal="OCI_APM_PUBLIC_DATAKEY=${OCI_APM_PUBLIC_DATAKEY}"} \
    ${OCI_APM_RUM_PUBLIC_DATAKEY:+--from-literal="OCI_APM_RUM_PUBLIC_DATAKEY=${OCI_APM_RUM_PUBLIC_DATAKEY}"} \
    --dry-run=client -o yaml | kubectl apply -f -

# ── Create configmap ──────────────────────────────────────────────
echo "[standalone] Creating configmap..."
cat <<CONFIGMAP_EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: crm-config
  namespace: ${NAMESPACE}
data:
  APP_NAME: "enterprise-crm-portal"
  BRAND_NAME: "${BRAND_NAME:-Enterprise CRM}"
  APP_VERSION: "1.1.0"
  APP_PORT: "8080"
  APP_ENV: "production"
  APP_RUNTIME: "oke"
  SERVICE_NAMESPACE: "crm"
  DNS_DOMAIN: "${DNS_DOMAIN}"
  CRM_BASE_URL: "${CRM_URL}"
  ORACLE_DSN: "${ORACLE_DSN}"
  ORACLE_USER: "${ORACLE_USER}"
  ORACLE_WALLET_DIR: "/app/wallet"
  DATABASE_OBSERVABILITY_ENABLED: "true"
  OTEL_SERVICE_NAME: "enterprise-crm-portal"
  OCI_APM_ENDPOINT: "${OCI_APM_ENDPOINT:-}"
  OCI_APM_RUM_ENDPOINT: "${OCI_APM_RUM_ENDPOINT:-}"
  OCI_AUTH_MODE: "${OCI_AUTH_MODE:-instance_principal}"
  OCTO_DRONE_SHOP_URL: "${OCTO_DRONE_SHOP_URL:-}"
  EXTERNAL_ORDERS_URL: "${OCTO_DRONE_SHOP_URL:-}"
  EXTERNAL_ORDERS_PATH: "/api/orders"
  ORDERS_SYNC_ENABLED: "${ORDERS_SYNC_ENABLED:-true}"
  ORDERS_SYNC_INTERVAL_SECONDS: "300"
  IDCS_DOMAIN_URL: "${IDCS_DOMAIN_URL:-}"
  IDCS_CLIENT_ID: "${IDCS_CLIENT_ID:-}"
  IDCS_REDIRECT_URI: "${IDCS_REDIRECT_URI}"
  SECURITY_LOG_ENABLED: "true"
  OTLP_LOG_EXPORT_ENABLED: "false"
CONFIGMAP_EOF

# ── Deploy ────────────────────────────────────────────────────────
# Match the security settings in deploy/k8s/ and keep the standalone wallet bindings.
echo "[standalone] Applying deployment with ${IMAGE_REF}..."
cat <<DEPLOY_EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: enterprise-crm-portal
  namespace: ${NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: enterprise-crm-portal
  template:
    metadata:
      labels:
        app: enterprise-crm-portal
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: crm
        image: "${IMAGE_REF}"
        securityContext:
          capabilities:
            drop: ["ALL"]
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: crm-config
        - secretRef:
            name: crm-secrets
        volumeMounts:
        - name: wallet
          mountPath: /app/wallet
          readOnly: true
        - name: tmp
          mountPath: /tmp
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 30
      volumes:
      - name: wallet
        secret:
          secretName: crm-wallet
      - name: tmp
        emptyDir:
          sizeLimit: 256Mi
---
apiVersion: v1
kind: Service
metadata:
  name: enterprise-crm-portal
  namespace: ${NAMESPACE}
spec:
  selector:
    app: enterprise-crm-portal
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
DEPLOY_EOF

# ── Wait for rollout ──────────────────────────────────────────────
echo "[standalone] Waiting for rollout..."
kubectl rollout status deployment/enterprise-crm-portal -n "$NAMESPACE" --timeout=120s

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Deployment complete!                                           ║"
echo "║                                                                 ║"
echo "║  Service: ClusterIP/enterprise-crm-portal in namespace ${NAMESPACE} ║"
echo "║  Health:  kubectl exec -n ${NAMESPACE} deploy/enterprise-crm-portal -- curl -s localhost:8080/health"
echo "║                                                                 ║"
echo "║  Next steps:                                                    ║"
echo "║  1. Create an OKE Ingress or LB Service pointing to port 80    ║"
echo "║  2. Configure DNS: crm.${DNS_DOMAIN} → LB IP                   ║"
echo "║  3. (Optional) Add TLS cert via cert-manager or OCI LB cert    ║"
echo "║  4. Login with the bootstrap admin credential from your secret ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
