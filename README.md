# security-flask-app

--

# Security for Flask App

## In Your Flask App

### 1. HTTP Security Headers
Use Flask-Talisman to easily set up all security headers:

```python
from flask_talisman import Talisman

app = Flask(__name__)
# Basic setup with CSP and all security headers
Talisman(app, 
         content_security_policy={
             'default-src': '\'self\'',
             'script-src': '\'self\'',
             'style-src': '\'self\'',
         },
         force_https=True)
```

### 2. CSRF Protection
Even with JWT, add CSRF protection:

```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)
```

### 3. JWT Cookie Settings
```python
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Strict'
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Short life
```

### 4. Turn Off Debug Mode in Production
```python
app.config['DEBUG'] = False
app.config['TESTING'] = False
```

### 5. Safe Logging
```python
import logging
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Log login attempts, errors, etc.
@app.after_request
def log_after_request(response):
    app.logger.info('%s %s %s %s %s', request.remote_addr, request.method, 
                    request.path, request.user_agent, response.status)
    return response
```

## Nginx Setup

### 1. HTTPS Setup
```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # Secure protocols and ciphers
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
    
    # HSTS (if not set in Flask-Talisman)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    # Other security headers (backup if Flask-Talisman fails)
    add_header X-Content-Type-Options "nosniff";
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    
    # Send requests to Flask app
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # Hide server details
        proxy_hide_header Server;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

### 2. Rate Limiting with Nginx
```nginx
# Set a limit zone
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

server {
    # ...
    
    # Apply rate limiting to sensitive endpoints
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        proxy_pass http://127.0.0.1:5000;
    }
}
```

## System Setup

### 1. Manage Secrets with Environment Variables
Create a `.env` file for your app (don’t version it) or use a secret manager, then:

```python
# In your Flask app
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
```

### 2. Update Dependencies Regularly
Check your dependencies for vulnerabilities:
```bash
pip install safety
safety check
```

### 3. Firewall and Monitoring
- Set up UFW (Uncomplicated Firewall) on your server
- Watch logs with tools like Datadog, Sentry, or ELK Stack

These steps cover the main recommended security measures. Do you want more details on any part?
