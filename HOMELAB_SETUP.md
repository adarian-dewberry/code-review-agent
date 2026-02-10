# 🏠 Frankie Homelab Setup

Get **Frankie** running on your home server, laptop, or local machine in minutes. No Docker expertise required.

---

## ⚡ Quick Start (2 minutes)

### Prerequisites
- Docker & Docker Compose installed ([Get Docker](https://docs.docker.com/get-docker/))
- `ANTHROPIC_API_KEY` environment variable set
- Git installed

### One-Liner Setup

```bash
git clone https://github.com/adarian-dewberry/code-review-agent.git
cd code-review-agent
docker-compose up
```

That's it! Open **http://localhost:7860** in your browser.

---

## 🐍 Local Python Setup (No Docker)

If you prefer running directly on your system:

### 1. Clone Repository
```bash
git clone https://github.com/adarian-dewberry/code-review-agent.git
cd code-review-agent
```

### 2. Set Up Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Set API Key

**Windows (PowerShell):**
```powershell
$env:ANTHROPIC_API_KEY = "your-api-key-here"
```

**macOS/Linux:**
```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

### 5. Run Frankie

**Web UI (Gradio):**
```bash
python app.py
```
Open http://localhost:7860

**CLI Mode:**
```bash
frankie review /path/to/code.py
```

---

## 🐳 Docker Setup (Recommended)

### Why Docker?
- Isolated environment (no Python version conflicts)
- Works identically on Windows, Mac, Linux
- Easy to stop/start/update
- Great for homelabs and NAS systems

### Setup Steps

1. **Clone & Navigate**
   ```bash
   git clone https://github.com/adarian-dewberry/code-review-agent.git
   cd code-review-agent
   ```

2. **Create `.env` file** (optional but recommended)
   ```bash
   echo "ANTHROPIC_API_KEY=your-api-key-here" > .env
   ```

3. **Start Frankie**
   ```bash
   docker-compose up
   ```

4. **Access Web UI**
   - Open http://localhost:7860
   - Or access from another computer: `http://<your-homelab-ip>:7860`

### Useful Docker Commands

```bash
# Run in background
docker-compose up -d

# View logs
docker-compose logs -f frankie

# Stop Frankie
docker-compose stop

# Restart
docker-compose restart

# Full cleanup
docker-compose down
```

---

## 🖥️ Platform-Specific Guides

### Windows 10/11

1. Install [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
2. Ensure WSL 2 is enabled ([Guide](https://docs.microsoft.com/en-us/windows/wsl/install))
3. Follow "Docker Setup" steps above

### macOS (Intel/Apple Silicon)

1. Install [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)
2. Follow "Docker Setup" steps above
3. Note: Apple Silicon runs natively; Intel uses emulation but still works

### Linux (Ubuntu/Debian)

```bash
sudo apt-get install docker.io docker-compose
sudo usermod -aG docker $USER  # Run without sudo
# Log out and back in
git clone https://github.com/adarian-dewberry/code-review-agent.git
cd code-review-agent
docker-compose up
```

### NAS Systems (Synology, TrueNAS, etc.)

Most NAS systems support Docker packages:
1. Install Docker from package manager
2. Use SSH to run:
   ```bash
   docker-compose up
   ```
3. Access via NAS IP + port 7860

---

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project directory:

```bash
# Required
ANTHROPIC_API_KEY=sk-...

# Optional - customize behavior
GRADIO_SERVER_NAME=0.0.0.0
GRADIO_SERVER_PORT=7860

# Optional - governance thresholds (for CLI/CI)
BLOCK_THRESHOLD=critical:0.8,high:0.95
REVIEW_THRESHOLD=high:0.7
```

### Port Customization

Edit `docker-compose.yml` to use a different port:

```yaml
services:
  frankie:
    ports:
      - "8080:7860"  # Access via http://localhost:8080
```

---

## 📝 Usage Examples

### Web UI
1. Paste code into the text area
2. Select review options (security, compliance, logic, performance)
3. Click "Analyze"
4. Review results with Frankie's guidance

### CLI (Local Python Only)

```bash
# Review a single file
frankie review app.py

# Review a Python file with CI mode (fail on critical issues)
frankie review --ci-mode app.py

# Review from stdin (git diff)
git diff | frankie review --stdin

# Specify config file
frankie review --config config.yaml app.py
```

### Docker CLI Usage

```bash
# Review file in mounted volume
docker-compose run frankie frankie review /repo/app.py

# Interactive mode
docker-compose run -it frankie /bin/bash
```

---

## 🔌 Accessing From Other Computers

### On Your Network

```bash
# Find your homelab IP
hostname -I  # Linux/Mac
ipconfig     # Windows
```

Then access: `http://<your-homelab-ip>:7860`

### Remote Access (VPN)

For accessing outside your network, use a VPN or reverse proxy:
1. Set up WireGuard/Tailscale on your homelab
2. Access Frankie through VPN tunnel
3. **Never expose port 7860 directly to internet**

---

## 🐛 Troubleshooting

### "docker-compose: command not found"
- Install Docker Compose: https://docs.docker.com/compose/install/
- Or use: `docker compose` (newer versions)

### "API Key not working"
```bash
# Verify API key is set
docker-compose exec frankie env | grep ANTHROPIC

# Restart with correct key
docker-compose down
export ANTHROPIC_API_KEY="your-key"
docker-compose up
```

### "Port 7860 already in use"
```bash
# Find what's using the port
lsof -i :7860      # macOS/Linux
netstat -ano | findstr :7860  # Windows

# Or use different port in docker-compose.yml
```

### "Out of memory" or slow performance
- Docker allocates resources from host OS
- In Docker Desktop settings, increase CPU/Memory allocated
- Or review smaller code chunks

### Container won't start
```bash
# Check logs
docker-compose logs frankie

# Rebuild image
docker-compose build --no-cache
docker-compose up
```

---

## 📦 Upgrading Frankie

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker-compose build --no-cache
docker-compose up -d
```

---

## 🤝 Integration with CI/CD

See [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) for:
- GitHub Actions workflows
- GitLab CI pipelines
- Jenkins integration
- Pre-commit hooks
- Multi-language examples (Node.js, Go, Bash)

---

## 📚 More Info

- [Main Documentation](README.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Usage Guide](USAGE.md)
- [Integration Guide](INTEGRATION_GUIDE.md)
- [Policies](POLICIES.md)

---

## 💬 Questions or Issues?

1. Check troubleshooting section above
2. Open an issue: https://github.com/adarian-dewberry/code-review-agent/issues
3. See [CONTRIBUTING.md](CONTRIBUTING.md)

Happy reviewing! 🐕
