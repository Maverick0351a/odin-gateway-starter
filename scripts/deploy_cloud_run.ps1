param(
  [Parameter(Mandatory=$true)][string]$Project,
  [string]$Region = "us-central1",
  [string]$RepoLocation = "us",  # Artifact Registry location (multi-region 'us')
  [string]$GatewayService = "odin-gateway",
  [string]$DashboardService = "odin-dashboard",
  [string]$GatewayRepo = "odin-gateway",
  [string]$DashboardRepo = "odin-dashboard",
  [switch]$Build
)

$ErrorActionPreference = "Stop"
Write-Host "Project: $Project  Region: $Region"

# Enable required GCP APIs
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com --project $Project

# Ensure Artifact Registry repositories exist
Write-Host "Ensuring Artifact Registry repositories ($RepoLocation) ..."
gcloud artifacts repositories describe $GatewayRepo --location=$RepoLocation --project $Project 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Creating repo $GatewayRepo"
  gcloud artifacts repositories create $GatewayRepo --repository-format=docker --location=$RepoLocation --description="ODIN gateway images" --project $Project
}
gcloud artifacts repositories describe $DashboardRepo --location=$RepoLocation --project $Project 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Creating repo $DashboardRepo"
  gcloud artifacts repositories create $DashboardRepo --repository-format=docker --location=$RepoLocation --description="ODIN dashboard images" --project $Project
}

# Create dashboard Dockerfile if missing
$dfDash = "Dockerfile.dashboard"
if (-not (Test-Path $dfDash)) {
  @"
FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
ENV PORT=8080
CMD ["bash","-lc","uvicorn services.dashboard.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
"@ | Out-File -Encoding UTF8 $dfDash
  Write-Host "Wrote $dfDash"
}

$GW_IMG = "$RepoLocation-docker.pkg.dev/$Project/$GatewayRepo/odin-gateway:latest"
$DB_IMG = "$RepoLocation-docker.pkg.dev/$Project/$DashboardRepo/odin-dashboard:latest"

if ($Build) {
  Write-Host "Building images via Cloud Build (temp Dockerfile swap)..."
  $existingDockerfile = $null
  $hadDockerfile = Test-Path ./Dockerfile

  if ($hadDockerfile) {
    $existingDockerfile = Get-Content -Raw ./Dockerfile
  }
  try {
    # Gateway image build
    Copy-Item -Force Dockerfile.gateway Dockerfile
  Write-Host "Building gateway image: $GW_IMG"
    gcloud builds submit --tag $GW_IMG --project $Project .
    if ($LASTEXITCODE -ne 0) { throw "Gateway image build failed" }

    # Dashboard image build
    if (-not (Test-Path Dockerfile.dashboard)) { throw "Dockerfile.dashboard missing" }
    Copy-Item -Force Dockerfile.dashboard Dockerfile
  Write-Host "Building dashboard image: $DB_IMG"
    gcloud builds submit --tag $DB_IMG --project $Project .
    if ($LASTEXITCODE -ne 0) { throw "Dashboard image build failed" }
  }
  finally {
    if ($hadDockerfile) {
      Set-Content -NoNewline -Encoding UTF8 Dockerfile $existingDockerfile
    } else {
      if (Test-Path Dockerfile) { Remove-Item Dockerfile -Force }
    }
  }
}

# Generate keypair if env not set
if (-not $env:ODIN_GATEWAY_PRIVATE_KEY_B64 -or -not $env:ODIN_GATEWAY_KID) {
  Write-Host "Generating gateway keys..."
  $gen = python scripts\gen_keys.py | Out-String
  # Parse current output format (ODIN_GATEWAY_PRIVATE_KEY_B64= ...)
  $priv = [regex]::Match($gen,'ODIN_GATEWAY_PRIVATE_KEY_B64=\s*([A-Za-z0-9_-]+)').Groups[1].Value
  $kid  = [regex]::Match($gen,'ODIN_GATEWAY_KID=\s*([A-Za-z0-9_-]+)').Groups[1].Value
  if (-not $priv -or -not $kid) { throw "Failed to parse key generation output" }
  $env:ODIN_GATEWAY_PRIVATE_KEY_B64 = $priv
  $env:ODIN_GATEWAY_KID = $kid
}

# Deploy gateway
Write-Host "Deploying $GatewayService ..."
$helRaw = $env:HEL_ALLOWLIST
if ($helRaw) {
  # Remove whitespace and replace '/' with placeholder to avoid any parsing ambiguity
  $helSanitized = ($helRaw -replace '\s','').Replace('/','__SL__')
} else { $helSanitized = '' }
$GATEWAY_URL = (gcloud run deploy $GatewayService `
  --image $GW_IMG --region $Region --platform managed --allow-unauthenticated `
  --set-env-vars "ODIN_GATEWAY_PRIVATE_KEY_B64=$env:ODIN_GATEWAY_PRIVATE_KEY_B64,ODIN_GATEWAY_KID=$env:ODIN_GATEWAY_KID,HEL_ALLOWLIST=$helSanitized" `
  --format="value(status.url)" --project $Project)

if (-not $GATEWAY_URL) { throw "Failed to obtain Gateway URL" }
Write-Host "Gateway URL: $GATEWAY_URL"

# Deploy dashboard
Write-Host "Deploying $DashboardService ..."
$DASHBOARD_URL = (gcloud run deploy $DashboardService `
  --image $DB_IMG --region $Region --platform managed --allow-unauthenticated `
  --set-env-vars "GATEWAY_URL=$GATEWAY_URL" `
  --format="value(status.url)" --project $Project)

if (-not $DASHBOARD_URL) { throw "Failed to obtain Dashboard URL" }
Write-Host "Dashboard URL: $DASHBOARD_URL"

# Smoke checks
Write-Host "Smoke check: Gateway /healthz"
try {
  $resp = Invoke-WebRequest "$GATEWAY_URL/healthz" -UseBasicParsing -TimeoutSec 20
  Write-Host "Gateway healthz: $($resp.StatusCode)"
} catch {
  Write-Warning "Gateway health failed: $($_.Exception.Message)"
}

Write-Host "Smoke check: Dashboard /"
try {
  $resp = Invoke-WebRequest "$DASHBOARD_URL" -UseBasicParsing -TimeoutSec 20
  Write-Host "Dashboard root: $($resp.StatusCode)"
} catch {
  Write-Warning "Dashboard check failed: $($_.Exception.Message)"
}

Write-Host "`nDone."
Write-Host "Gateway:   $GATEWAY_URL"
Write-Host "Dashboard: $DASHBOARD_URL"
