# Cloudflare Token Collector & API Tester


## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd doscrape
```

2. Build the Docker image for token collection:
```bash
make build-container
```

3. Run the application:
```bash
go run .
```

5. Open your browser and navigate to `http://localhost:8080`


### Token Collection Process
1. Docker containers are launched with target URL
2. Each container runs browser to bypass Cloudflare
3. Cookies and User-Agent are extracted
4. Tokens are stored with 4-minute expiry
5. Failed tokens are automatically removed

### Dynamic Rate Control
- **0 tokens**: Pause requests
- **80-100 tokens**: 20 req/sec
- **100-150 tokens**: 30 req/sec
- **150+ tokens**: 40 req/sec
