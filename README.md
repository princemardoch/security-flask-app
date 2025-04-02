# security-flask-app

## Dans votre application Flask

### 1. En-têtes de sécurité HTTP
Utilisez Flask-Talisman pour configurer facilement tous les en-têtes de sécurité :

```python
from flask_talisman import Talisman

app = Flask(__name__)
# Configuration basique avec CSP et tous les en-têtes de sécurité
Talisman(app, 
         content_security_policy={
             'default-src': '\'self\'',
             'script-src': '\'self\'',
             'style-src': '\'self\'',
         },
         force_https=True)
```

### 2. Protection CSRF
Même avec JWT, ajoutez une protection CSRF :

```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)
```

### 3. Configuration des cookies JWT
```python
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Strict'
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Courte durée de vie
```

### 4. Désactiver le mode debug en production
```python
app.config['DEBUG'] = False
app.config['TESTING'] = False
```

### 5. Logging sécurisé
```python
import logging
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Logging des tentatives d'authentification, erreurs, etc.
@app.after_request
def log_after_request(response):
    app.logger.info('%s %s %s %s %s', request.remote_addr, request.method, 
                    request.path, request.user_agent, response.status)
    return response
```

## Configuration Nginx

### 1. Configuration HTTPS
```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # Protocoles et chiffrements sécurisés
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
    
    # HSTS (si pas déjà configuré via Flask-Talisman)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    # Autres en-têtes de sécurité (redondance avec Flask-Talisman mais utile comme fallback)
    add_header X-Content-Type-Options "nosniff";
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    
    # Redirection des requêtes vers l'app Flask
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # Cacher les détails du serveur
        proxy_hide_header Server;
    }
}

# Redirection de HTTP vers HTTPS
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

### 2. Rate limiting avec Nginx
```nginx
# Définir une zone de limitation
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

server {
    # ...
    
    # Appliquer le rate limiting sur les endpoints sensibles
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        proxy_pass http://127.0.0.1:5000;
    }
}
```

## Configuration du système

### 1. Gestion des secrets avec variables d'environnement
Créez un fichier `.env` pour votre application (ne le versionnez pas) ou utilisez un gestionnaire de secrets, puis :

```python
# Dans votre app Flask
import os
from dotenv import load_dotenv

load_dotenv()  # Charger les variables d'environnement
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
```

### 2. Mise à jour régulière des dépendances
Vérifiez vos dépendances pour des vulnérabilités :
```bash
pip install safety
safety check
```

### 3. Pare-feu et monitoring
- Configurer UFW (Uncomplicated Firewall) sur votre serveur
- Surveiller les logs avec un outil comme Datadog, Sentry ou ELK Stack

Ces implémentations couvrent l'essentiel des mesures de sécurité recommandées. Souhaitez-vous des détails supplémentaires sur l'un de ces aspects en particulier ?
