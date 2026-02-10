# Frankie - AI Code Review Agent (PowerShell Wrapper)
# Windows homelab edition - zero Docker experience needed
#
# Usage:
#   .\frankie.ps1 review .\app.py
#   .\frankie.ps1 docker
#   Get-Content app.py | .\frankie.ps1 stdin
#   .\frankie.ps1 ci .\src

param(
    [Parameter(Position = 0)]
    [string]$Command = "help",
    
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommandPath
$ApiKey = $env:ANTHROPIC_API_KEY
$DockerImage = "frankie-review:latest"

function Show-Usage {
    @"
🐕 Frankie - AI Code Review Agent

Usage:
    .\frankie.ps1 review <path>      Review file locally
    .\frankie.ps1 docker <path>      Review in Docker
    .\frankie.ps1 stdin              Review from stdin (pipeline)
    .\frankie.ps1 ci <path>          CI/CD mode (strict)
    .\frankie.ps1 web                Start web UI (Gradio)
    .\frankie.ps1 help               Show this help

Examples:
    .\frankie.ps1 review app.py
    .\frankie.ps1 docker src\
    Get-Content vulnerable.py | .\frankie.ps1 stdin
    .\frankie.ps1 ci app.py --confidence-threshold 0.8

Environment Variables:
    ANTHROPIC_API_KEY   (Required) Your Claude API key
    RATE_LIMIT_REQUESTS (Optional) Requests per window (default: 10)
    RATE_LIMIT_WINDOW   (Optional) Window in seconds (default: 60)

"@
}

function Test-Prerequisites {
    if (-not $ApiKey) {
        Write-Host "❌ ANTHROPIC_API_KEY not set" -ForegroundColor Red
        Write-Host "Set it with: `$env:ANTHROPIC_API_KEY = 'your-api-key'" -ForegroundColor Yellow
        exit 1
    }
}

function Test-Docker {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        Write-Host "❌ Docker not found. Install from https://docs.docker.com/get-docker/" -ForegroundColor Red
        exit 1
    }
}

function Test-Python {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        Write-Host "❌ Python 3.10+ not found. Install from https://www.python.org/downloads/" -ForegroundColor Red
        exit 1
    }
}

function Invoke-Review {
    param([string]$Path)
    
    Test-Prerequisites
    Test-Python
    
    if (-not (Test-Path $Path)) {
        Write-Host "❌ Path not found: $Path" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "🐕 Frankie is reviewing $Path..." -ForegroundColor Cyan
    Write-Host "---"
    
    Push-Location $ScriptDir
    try {
        $env:ANTHROPIC_API_KEY = $ApiKey
        & python -m code_review_agent.cli review $Path @Args
    }
    finally {
        Pop-Location
    }
}

function Invoke-Docker {
    param([string]$Path = ".")
    
    Test-Prerequisites
    Test-Docker
    
    $ResolvedPath = (Resolve-Path $Path).Path
    
    Write-Host "🐳 Building Docker image..." -ForegroundColor Cyan
    docker build -t $DockerImage $ScriptDir
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Docker build failed" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "🐕 Running Frankie in Docker..." -ForegroundColor Cyan
    docker run --rm `
        -v "${ResolvedPath}:/repo:ro" `
        -e "ANTHROPIC_API_KEY=$ApiKey" `
        $DockerImage `
        frankie review /repo
}

function Invoke-Stdin {
    Test-Prerequisites
    Test-Python
    
    Write-Host "🐕 Reading code from stdin..." -ForegroundColor Cyan
    
    Push-Location $ScriptDir
    try {
        $env:ANTHROPIC_API_KEY = $ApiKey
        $input | & python -m code_review_agent.cli review --stdin @Args
    }
    finally {
        Pop-Location
    }
}

function Invoke-CI {
    param([string]$Path)
    
    Test-Prerequisites
    Test-Python
    
    if (-not (Test-Path $Path)) {
        Write-Host "❌ File not found: $Path" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "🔒 CI/CD Mode: Strict checking enabled" -ForegroundColor Yellow
    Write-Host "⚠️  Build will fail on critical/high-confidence issues"
    
    Push-Location $ScriptDir
    try {
        $env:ANTHROPIC_API_KEY = $ApiKey
        $env:BLOCK_THRESHOLD = "critical:0.8,high:0.95"
        $env:REVIEW_THRESHOLD = "high:0.7"
        
        & python -m code_review_agent.cli review --ci-mode $Path @Args
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ CI check failed: critical issues found" -ForegroundColor Red
            exit 1
        }
    }
    finally {
        Pop-Location
    }
}

function Invoke-Web {
    Test-Prerequisites
    Test-Python
    
    Write-Host "🌐 Starting Frankie web UI..." -ForegroundColor Cyan
    Write-Host "Open http://localhost:7860 in your browser" -ForegroundColor Green
    
    Push-Location $ScriptDir
    try {
        $env:ANTHROPIC_API_KEY = $ApiKey
        & python app.py
    }
    finally {
        Pop-Location
    }
}

# Main dispatcher
switch ($Command.ToLower()) {
    "review" {
        if ($Args.Count -eq 0) {
            Write-Host "❌ Please specify a file or directory" -ForegroundColor Red
            Show-Usage
            exit 1
        }
        Invoke-Review -Path $Args[0]
    }
    
    "docker" {
        $path = if ($Args.Count -gt 0) { $Args[0] } else { "." }
        Invoke-Docker -Path $path
    }
    
    "stdin" {
        Invoke-Stdin
    }
    
    "ci" {
        if ($Args.Count -eq 0) {
            Write-Host "❌ Please specify a file" -ForegroundColor Red
            Show-Usage
            exit 1
        }
        Invoke-CI -Path $Args[0]
    }
    
    "web" {
        Invoke-Web
    }
    
    "help" {
        Show-Usage
    }
    
    default {
        Write-Host "❌ Unknown command: $Command" -ForegroundColor Red
        Show-Usage
        exit 1
    }
}
