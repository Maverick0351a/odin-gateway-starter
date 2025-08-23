Param(
    [Parameter(Mandatory = $true)] [string]$Project,
    [string]$Region = "us-central1",
    [switch]$Build,
    [string]$Repo = "odin",                   # Artifact Registry repo (Docker format)
    [string]$GatewayService = "odin-gateway",
    [string]$DashboardService = "odin-dashboard",
    [string]$GatewayDockerfile = "Dockerfile.gateway",
    [string]$DashboardDockerfile = "Dockerfile.dashboard",
    [string]$GatewayPort = "8080",
    [string]$DashboardPort = "8081",
    [switch]$DeployDashboard
)

<#
.SYNOPSIS
  Build & deploy ODIN Gateway (and optional Dashboard) to Google Cloud Run.

.DESCRIPTION
  Convenience wrapper around gcloud builds submit & gcloud run deploy.
  Expects gcloud CLI authenticated and appropriate IAM permissions.

  REQUIRED ENV VARS (for secure signing):
    ODIN_GATEWAY_PRIVATE_KEY_B64  - 32-byte Ed25519 seed (base64url, no padding)
    ODIN_GATEWAY_KID              - Key identifier string

  OPTIONAL ENV VARS:
    ODIN_ADDITIONAL_PUBLIC_JWKS   - JSON string of extra public keys
    ODIN_API_KEY_SECRETS          - JSON map of api_key->secret for HMAC layer
    FIRESTORE_PROJECT             - Enables Firestore receipt backend (ADC must be configured)
    RECEIPT_LOG_PATH              - Override local JSONL path (when not using Firestore)

  USAGE:
    ./scripts/deploy_cloud_run.ps1 -Project my-gcp-proj -Region us-central1 -Build
    ./scripts/deploy_cloud_run.ps1 -Project my-gcp-proj -DeployDashboard

  NOTES:
    * If -Build omitted, script assumes images already exist in Artifact Registry.
    * Artifact Registry repo must exist (Docker format). Create once:
        gcloud artifacts repositories create $Repo --repository-format=docker --location=$Region --description="ODIN images"
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info($msg){ Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg){ Write-Host "[ERR ] $msg" -ForegroundColor Red }

Write-Info "Project: $Project | Region: $Region"

# Validate gcloud
if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    Write-Err "gcloud CLI not found in PATH."; exit 1
}

Write-Info "Setting active project"
gcloud config set project $Project | Out-Null

$GatewayImage = "$Region-docker.pkg.dev/$Project/$Repo/$GatewayService:latest"
$DashboardImage = "$Region-docker.pkg.dev/$Project/$Repo/$DashboardService:latest"

if ($Build) {
    Write-Info "Building & pushing gateway image: $GatewayImage"
    gcloud builds submit --config <# implicit #> --tag $GatewayImage --region $Region --project $Project --timeout=900 -f $GatewayDockerfile .
    if ($DeployDashboard) {
        Write-Info "Building & pushing dashboard image: $DashboardImage"
        gcloud builds submit --tag $DashboardImage --region $Region --project $Project --timeout=900 -f $DashboardDockerfile .
    }
}
else {
    Write-Warn "-Build not set; skipping image build. Assuming images already exist."
}

# Gateway deploy
Write-Info "Deploying Cloud Run service: $GatewayService"

$gatewayEnv = @()
foreach ($name in 'ODIN_GATEWAY_PRIVATE_KEY_B64','ODIN_GATEWAY_KID','ODIN_ADDITIONAL_PUBLIC_JWKS','ODIN_API_KEY_SECRETS','FIRESTORE_PROJECT','RECEIPT_LOG_PATH') {
    if ($env:$name) { $gatewayEnv += "$name=$($env:$name)" }
}
if (-not ($gatewayEnv | Where-Object { $_ -like 'ODIN_GATEWAY_PRIVATE_KEY_B64*'})) {
    Write-Warn "ODIN_GATEWAY_PRIVATE_KEY_B64 not present in environment; deployment will generate an ephemeral key (not recommended for prod)."
}

gcloud run deploy $GatewayService `
  --image $GatewayImage `
  --platform managed `
  --region $Region `
  --allow-unauthenticated `
  --port $GatewayPort `
  --cpu 1 `
  --memory 512Mi `
  --execution-environment gen2 `
  --set-env-vars ($gatewayEnv -join ',')

$GatewayURL = (gcloud run services describe $GatewayService --region $Region --format='value(status.url)')
Write-Info "Gateway URL: $GatewayURL"

if ($DeployDashboard) {
    Write-Info "Deploying Cloud Run service: $DashboardService"
    $dashEnv = @("GATEWAY_URL=$GatewayURL")
    gcloud run deploy $DashboardService `
      --image $DashboardImage `
      --platform managed `
      --region $Region `
      --allow-unauthenticated `
      --port $DashboardPort `
      --cpu 1 `
      --memory 256Mi `
      --execution-environment gen2 `
      --set-env-vars ($dashEnv -join ',')
    $DashboardURL = (gcloud run services describe $DashboardService --region $Region --format='value(status.url)')
    Write-Info "Dashboard URL: $DashboardURL"
}

Write-Info "Performing smoke health check..."
try {
    $health = (Invoke-RestMethod -Uri "$GatewayURL/healthz" -TimeoutSec 10)
    Write-Info "Health: $(ConvertTo-Json $health -Compress)"
} catch {
    Write-Warn "Health check failed: $($_.Exception.Message)"
}

Write-Info "Done."
