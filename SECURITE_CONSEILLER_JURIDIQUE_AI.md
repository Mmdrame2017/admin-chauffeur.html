# 🔐 Guide de Sécurité - Conseiller Juridique AI

**Date** : 2026-02-20
**Workflow n8n** : `LMpYuAfog3dubOJn` ("Conseiller Juridique AI - Sénégal")
**Token actuel** : `CJ_SN_2026_69cc58b499401bd22cb9f29f5bc7e18b` (rotation 2026-02-20 10:00 UTC)
**Ancien token** : ~~`CJ_SN_2026_69cc58b499401bd22cb9f29f5bc7e18b`~~ (révoqué)

---

## 📋 Résumé des modifications

### Frontend (✅ DÉPLOYÉ)
- Constante `API_SECRET` ajoutée dans les deux fichiers HTML
- Header `X-API-Key` envoyé automatiquement dans toutes les requêtes
- Fichiers modifiés :
  - `conseiller-juridique-ai.html` (source)
  - `conseiller-juridique-ai/index.html` (déployé sur Vercel)

### Backend n8n (⚠️ À IMPLÉMENTER)
3 nodes à ajouter dans le workflow :
1. **Auth Verification** - Vérification du token
2. **Rate Limiting** - Limitation à 10 requêtes/min
3. **CORS Configuration** - Configuration dans le Webhook

---

## 🛠️ ÉTAPES D'IMPLÉMENTATION N8N

### 🔹 ÉTAPE 1 : Ajouter le node "Auth Verification"

**Position** : Juste après le Webhook, avant "Classify&Extract"

```
Webhook → [AUTH VERIFICATION] → Classify&Extract → ...
```

#### Configuration du node :
- **Type** : Code
- **Name** : Auth Verification
- **Mode** : Run Once for All Items
- **Continue On Fail** : ❌ DÉSACTIVÉ

#### Code JavaScript à copier :
```javascript
// Vérification du token d'authentification
const API_SECRET = 'CJ_SN_2026_69cc58b499401bd22cb9f29f5bc7e18b';

const items = $input.all();
const headers = items[0].json.headers || {};
const providedKey = headers['x-api-key'];

if (!providedKey || providedKey !== API_SECRET) {
  // Token invalide ou absent - retourner erreur 401
  return [{
    json: {
      error: 'Accès non autorisé. Clé API manquante ou invalide.',
      status: 401,
      authenticated: false
    }
  }];
}

// Token valide - continuer le workflow
return [{
  json: {
    ...items[0].json,
    authenticated: true
  }
}];
```

#### Connexion :
- **Input** : Webhook
- **Output** : Rate Limiting (voir étape suivante)

---

### 🔹 ÉTAPE 2 : Ajouter le node "Rate Limiting"

**Position** : Après Auth Verification, avant Classify&Extract

```
Auth Verification → [RATE LIMITING] → Classify&Extract → ...
```

#### Configuration du node :
- **Type** : Code
- **Name** : Rate Limiting
- **Mode** : Run Once for All Items
- **Continue On Fail** : ❌ DÉSACTIVÉ

#### Code JavaScript à copier :
```javascript
// Rate limiting : maximum 10 requêtes par minute par IP
const RATE_LIMIT = 10;        // nombre max de requêtes
const TIME_WINDOW = 60 * 1000; // fenêtre de 1 minute (en millisecondes)

const items = $input.all();
const headers = items[0].json.headers || {};

// Récupérer l'IP du client (proxy-aware)
const clientIP = headers['x-forwarded-for']?.split(',')[0]?.trim()
  || headers['x-real-ip']
  || headers['cf-connecting-ip'] // Cloudflare
  || 'unknown';

// Utiliser le Static Data du workflow (attention : volatile, réinitialisé au redémarrage)
// En production, utiliser une base Redis ou PostgreSQL externe
const now = Date.now();

// Initialiser ou récupérer le cache de rate limiting
if (!$execution.customData) {
  $execution.customData = { rateLimits: {} };
}

const rateLimitData = $execution.customData.rateLimits || {};

// Nettoyer les entrées expirées (> 1 minute)
Object.keys(rateLimitData).forEach(ip => {
  if (now - rateLimitData[ip].resetTime > TIME_WINDOW) {
    delete rateLimitData[ip];
  }
});

// Vérifier le rate limit pour cette IP
if (!rateLimitData[clientIP]) {
  // Première requête de cette IP
  rateLimitData[clientIP] = {
    count: 1,
    resetTime: now,
    firstRequestTime: now
  };
} else {
  const ipData = rateLimitData[clientIP];

  if (now - ipData.resetTime > TIME_WINDOW) {
    // Fenêtre expirée, réinitialiser
    rateLimitData[clientIP] = {
      count: 1,
      resetTime: now,
      firstRequestTime: now
    };
  } else {
    // Incrémenter le compteur
    ipData.count++;

    if (ipData.count > RATE_LIMIT) {
      // Limite dépassée - retourner erreur 429
      const retryAfter = Math.ceil((TIME_WINDOW - (now - ipData.resetTime)) / 1000);

      return [{
        json: {
          error: `Trop de requêtes. Vous avez atteint la limite de ${RATE_LIMIT} requêtes par minute.`,
          status: 429,
          retryAfter: retryAfter,
          limit: RATE_LIMIT,
          remaining: 0,
          resetTime: new Date(ipData.resetTime + TIME_WINDOW).toISOString()
        }
      }];
    }
  }
}

// Sauvegarder l'état mis à jour
$execution.customData.rateLimits = rateLimitData;

// Ajouter les headers de rate limiting (style GitHub API)
const ipData = rateLimitData[clientIP];
return [{
  json: {
    ...items[0].json,
    rateLimitInfo: {
      limit: RATE_LIMIT,
      remaining: Math.max(0, RATE_LIMIT - ipData.count),
      resetTime: new Date(ipData.resetTime + TIME_WINDOW).toISOString(),
      clientIP: clientIP
    }
  }
}];
```

#### Connexion :
- **Input** : Auth Verification
- **Output** : Classify&Extract

---

### 🔹 ÉTAPE 3 : Modifier le node "Respond to Webhook"

Le node final doit gérer 3 types de réponses :
- ✅ **200** : Réponse normale (authentifié + sous limite)
- ❌ **401** : Accès non autorisé (mauvais token)
- ⏱️ **429** : Trop de requêtes (rate limit dépassé)

#### Configuration :
- **Respond With** : Using Fields Below
- **Response Code** : `{{ $json.status || 200 }}`
- **Response Headers** : Ajouter ces headers

| Nom | Valeur |
|-----|--------|
| `Content-Type` | `application/json` |
| `X-RateLimit-Limit` | `{{ $json.rateLimitInfo?.limit || 10 }}` |
| `X-RateLimit-Remaining` | `{{ $json.rateLimitInfo?.remaining || 0 }}` |
| `Retry-After` | `{{ $json.retryAfter || 60 }}` |

#### Response Body :
```javascript
{{
  $json.error
    ? {
        error: $json.error,
        status: $json.status,
        retryAfter: $json.retryAfter,
        timestamp: new Date().toISOString()
      }
    : {
        response: $json.response,
        type: $json.type,
        timestamp: new Date().toISOString()
      }
}}
```

---

### 🔹 ÉTAPE 4 : Configuration CORS du Webhook

Dans le node **Webhook** (tout premier node) :

#### Paramètres de base :
- **Path** : `/webhook/conseiller-juridique-ai`
- **HTTP Method** : POST
- **Authentication** : None (on utilise X-API-Key custom)
- **Response Mode** : When Last Node Finishes

#### Options → CORS :
- **Allowed Origin(s)** : `https://conseiller-juridique-ai.vercel.app`
- **Allowed Methods** : `POST, OPTIONS`
- **Allowed Headers** : `Content-Type, X-API-Key`
- **Credentials** : ✅ Enabled

---

## 🏗️ Architecture finale du workflow

```
┌─────────────────┐
│   Webhook       │  (CORS configuré)
└────────┬────────┘
         │
┌────────▼────────────────┐
│  Auth Verification      │  ← NOUVEAU
│  (vérifie X-API-Key)    │
│  ❌ 401 si invalide      │
└────────┬────────────────┘
         │ (si auth OK)
┌────────▼────────────────┐
│   Rate Limiting         │  ← NOUVEAU
│  (max 10/min par IP)    │
│  ⏱️ 429 si dépassé      │
└────────┬────────────────┘
         │ (si sous limite)
┌────────▼────────────────┐
│  Classify&Extract       │
└────────┬────────────────┘
         │
┌────────▼────────────────┐
│  Pre-Search ILIKE       │
└────────┬────────────────┘
         │
┌────────▼────────────────┐
│  Build Context          │
└────────┬────────────────┘
         │
┌────────▼────────────────┐
│  AI Legal Advisor       │
│  (GPT-4o-mini)          │
└────────┬────────────────┘
         │
┌────────▼────────────────┐
│  Clean Output           │
└────────┬────────────────┘
         │
┌────────▼────────────────┐
│  Respond to Webhook     │  ← MODIFIÉ
│  (gère 200/401/429)     │
└─────────────────────────┘
```

---

## 🧪 Tests à effectuer

### Test 1 : Authentification valide
```bash
curl -X POST https://mmdrame2017.app.n8n.cloud/webhook/conseiller-juridique-ai \
  -H "Content-Type: application/json" \
  -H "X-API-Key: CJ_SN_2026_69cc58b499401bd22cb9f29f5bc7e18b" \
  -d '{"message": "Test authentifié", "session_id": "test123"}'
```
**Résultat attendu** : 200 OK avec réponse de l'IA

---

### Test 2 : Authentification invalide
```bash
curl -X POST https://mmdrame2017.app.n8n.cloud/webhook/conseiller-juridique-ai \
  -H "Content-Type: application/json" \
  -H "X-API-Key: MAUVAIS_TOKEN" \
  -d '{"message": "Test non authentifié", "session_id": "test123"}'
```
**Résultat attendu** : 401 Unauthorized
```json
{
  "error": "Accès non autorisé. Clé API manquante ou invalide.",
  "status": 401,
  "timestamp": "2026-02-20T..."
}
```

---

### Test 3 : Rate limiting
```bash
# Envoyer 11 requêtes en 1 minute
for i in {1..11}; do
  curl -X POST https://mmdrame2017.app.n8n.cloud/webhook/conseiller-juridique-ai \
    -H "Content-Type: application/json" \
    -H "X-API-Key: CJ_SN_2026_69cc58b499401bd22cb9f29f5bc7e18b" \
    -d "{\"message\": \"Test $i\", \"session_id\": \"test123\"}"
  echo ""
done
```
**Résultat attendu** :
- Requêtes 1-10 : 200 OK
- Requête 11 : 429 Too Many Requests
```json
{
  "error": "Trop de requêtes. Vous avez atteint la limite de 10 requêtes par minute.",
  "status": 429,
  "retryAfter": 45,
  "limit": 10,
  "remaining": 0
}
```

---

## 🔄 Rotation du token API

Si le token `API_SECRET` est compromis, suivre ces étapes :

### 1. Générer un nouveau token
```javascript
// Dans la console browser ou Node.js
const crypto = require('crypto');
const newToken = 'CJ_SN_2026_' + crypto.randomBytes(16).toString('hex');
console.log(newToken);
```

### 2. Mettre à jour le frontend
Modifier dans les 2 fichiers HTML :
```javascript
const API_SECRET = 'NOUVEAU_TOKEN_ICI';
```

### 3. Mettre à jour n8n
Dans le node "Auth Verification", remplacer :
```javascript
const API_SECRET = 'NOUVEAU_TOKEN_ICI';
```

### 4. Déployer
```bash
git add .
git commit -m "security: Rotation token API"
git push
```

---

## 📊 Monitoring recommandé

Pour surveiller l'utilisation et détecter les abus :

### Métriques à suivre dans n8n :
1. **Nombre de 401** : Tentatives d'accès non autorisé
2. **Nombre de 429** : IPs qui dépassent la limite
3. **Top IPs** : Identifier les utilisateurs les plus actifs
4. **Temps de réponse moyen** : Détecter les ralentissements

### Amélioration future (production) :
- Remplacer `$execution.customData` par **Redis** ou **PostgreSQL**
- Ajouter un **whitelist d'IPs** (admins)
- Implémenter **JWT tokens** avec expiration
- Logger les accès dans **Supabase** pour analyse

---

## ⚠️ Limites actuelles

### Rate Limiting en mémoire :
- ❌ Les compteurs sont **réinitialisés au redémarrage** du workflow n8n
- ❌ Ne fonctionne **pas en mode distribué** (plusieurs instances n8n)
- ✅ Suffisant pour un projet MVP/prototype
- 🔄 Pour la production : migrer vers Redis/PostgreSQL

### Protection DDOS :
- ⚠️ Le rate limiting protège contre les **abus légers**
- ❌ Ne protège **pas contre un DDOS massif** (milliers de req/sec)
- 💡 Solution : Ajouter **Cloudflare** devant n8n pour :
  - Protection DDOS automatique
  - Cache CDN des réponses
  - WAF (Web Application Firewall)

---

## 🎯 Checklist de déploiement

- [x] ✅ Frontend : Ajout API_SECRET + header X-API-Key
- [x] ✅ Git : Commit + push des changements
- [ ] ⏳ n8n : Ajouter node "Auth Verification"
- [ ] ⏳ n8n : Ajouter node "Rate Limiting"
- [ ] ⏳ n8n : Modifier "Respond to Webhook"
- [ ] ⏳ n8n : Configurer CORS dans le Webhook
- [ ] ⏳ Tests : Vérifier auth valide (200)
- [ ] ⏳ Tests : Vérifier auth invalide (401)
- [ ] ⏳ Tests : Vérifier rate limiting (429)
- [ ] ⏳ Production : Tester depuis l'app Vercel

---

## 📞 Support

**Workflow n8n** : https://mmdrame2017.app.n8n.cloud/workflow/LMpYuAfog3dubOJn
**App déployée** : https://conseiller-juridique-ai.vercel.app/
**GitHub repo** : https://github.com/Mmdrame2017/conseiller-juridique-ai

---

**📅 Document créé le** : 2026-02-20
**👤 Auteur** : Claude Sonnet 4.5 + Moustapha DRAME
**🔒 Niveau de sécurité** : MVP/Prototype (améliorer pour production)
