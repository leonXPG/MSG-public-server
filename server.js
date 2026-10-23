#!/usr/bin/env node
/**
 * MESH RELAY SERVER — un seul fichier, zéro dépendance npm.
 *
 * Deux types de serveur :
 *  - "channels" : salons texte (historique persisté, clé de salon partagée
 *    entre membres) + salons vocaux (comme les salons texte) + partage
 *    d'écran, rôles owner/admin/membre, kick/ban, icône de serveur.
 *  - "mp"       : recherche d'utilisateur, demandes d'ami, blocage,
 *    MP 1-à-1 en direct (non stockés), + groupes MP (historique persisté
 *    comme les salons, avec régénération de clé si tout le monde se
 *    déconnecte, gestion des membres par le créateur du groupe).
 *
 * IMPORTANT — modèle de confidentialité :
 *  - Les MP 1-à-1 restent du chiffrement de bout en bout pur, jamais stockés.
 *  - Les salons et groupes MP utilisent une clé PARTAGÉE entre les membres
 *    (nécessaire pour que les nouveaux arrivants déchiffrent l'historique).
 *    Le serveur ne voit jamais cette clé ni le texte en clair, mais comme
 *    la clé circule entre plusieurs personnes (pas une seule paire), ce
 *    n'est plus le même niveau de garantie que du E2E pair-à-pair strict.
 *
 * SÉCURITÉ — CE QUE LE SERVEUR VÉRIFIE MAINTENANT :
 *  - Identité : un client ne peut plus prétendre être quelqu'un d'autre.
 *    À la connexion, il doit prouver par un défi cryptographique (ECDH +
 *    HMAC) qu'il possède bien la clé privée correspondant à la clé publique
 *    annoncée — l'empreinte ("fingerprint") est recalculée par le serveur
 *    lui-même à partir de cette clé publique, jamais acceptée telle quelle
 *    depuis le client. Impossible donc de voler l'identité, le statut
 *    owner/admin, ou l'historique d'amis de quelqu'un d'autre.
 *  - Robustesse : toute erreur de traitement d'un message est interceptée
 *    (elle ne fait jamais planter tout le processus), les tailles de trame
 *    WebSocket et de tampon sont plafonnées, un pare-feu anti-inondation
 *    limite le nombre de messages par connexion, et le nombre de connexions
 *    simultanées par IP est plafonné.
 *  - Permissions : owner/admin (serveurs) et créateur (groupes) restent
 *    strictement contrôlés côté serveur (jamais déductibles d'une donnée
 *    envoyée par le client).
 *
 * Lancement :   node server.js   (Node.js 16+ requis pour Web Crypto)
 * Premier lancement : http://localhost:8787 pour choisir nom / type / port / salons.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const nodeCrypto = require('crypto');
const fs = require('fs');
const path = require('path');

const CONFIG_PATH = path.join(__dirname, 'server-config.json');
const DATA_PATH = path.join(__dirname, 'server-data.json');
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'; // valeur exacte de la RFC 6455
const SETUP_PORT = 8787;
const MAX_HISTORY = 300;                   // messages conservés par salon / groupe
const RATE_LIMIT_MS = 1000;                // 1 message de chat / seconde / utilisateur
const MAX_FRAME_BYTES = 3 * 1024 * 1024;   // 3 Mo max par trame WebSocket
const MAX_BUFFER_BYTES = 6 * 1024 * 1024;  // 6 Mo max de données non-traitées en attente
const MAX_CONN_PER_IP = 12;                // connexions simultanées max par adresse IP
const MAX_MSGS_PER_WINDOW = 50;            // messages max par fenêtre d'1s -> coupe si dépassé (anti-flood générique)
const AUTH_TIMEOUT_MS = 8000;              // délai max pour répondre au défi d'authentification
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const KEY_LIKE_FIELDS = ['channel', 'groupId', 'scopeId', 'name', 'to', 'target', 'from'];

/* ---------- Web Crypto (intégré à Node depuis la v16) — nécessaire pour
   vérifier cryptographiquement l'identité des clients ---------- */
let subtle;
try{
  subtle = nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle;
  if(!subtle) throw new Error('Web Crypto indisponible');
}catch(e){
  console.error('\n✗ Ce serveur nécessite Node.js 16 ou plus récent (Web Crypto intégré) pour vérifier les identités en toute sécurité.');
  console.error('  Vérifie ta version avec `node --version` puis mets à jour Node.js.\n');
  process.exit(1);
}

/* ============================================================
   ÉTAPE 1 — pas de config -> page de réglage (premier lancement)
   ============================================================ */
function runSetupWizard(){
  const setupHtml = `<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<title>Réglage du serveur MSG</title>
<style>
  body{background:#0a0d13;color:#dbe2ee;font-family:'Segoe UI',sans-serif;
    display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
  .card{width:420px;background:#131822;border:1px solid #1f2632;border-radius:14px;padding:32px;}
  h1{font-size:22px;margin:0 0 6px;}
  p.sub{color:#7c8797;font-size:13px;line-height:1.5;margin:0 0 24px;}
  label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
    color:#7c8797;margin:16px 0 6px;}
  input,select{width:100%;padding:10px;background:#10141d;border:1px solid #1f2632;
    border-radius:8px;color:#dbe2ee;font-size:14px;box-sizing:border-box;}
  .choice{display:flex;gap:10px;margin-top:6px;}
  .choice label{flex:1;border:1px solid #1f2632;border-radius:8px;padding:12px;
    text-transform:none;letter-spacing:0;font-size:13px;cursor:pointer;margin:0;color:#dbe2ee;}
  .choice input{width:auto;display:inline;margin-right:8px;}
  button{width:100%;margin-top:24px;padding:12px;border:none;border-radius:8px;
    background:#4fe0c4;color:#04211c;font-weight:700;font-size:14px;cursor:pointer;}
</style></head>
<body>
  <div class="card">
    <h1>Configurer ce nœud</h1>
    <p class="sub">Ce réglage n'a lieu qu'une fois. server-config.json et server-data.json seront créés à côté de server.js.</p>
    <form method="POST" action="/setup">
      <label>Nom du serveur</label>
      <input name="name" placeholder="ex: Le Repaire" required>

      <label>Icône (symbole ou courte étiquette)</label>
      <input name="icon" placeholder="ex: ⚉ ou LR" maxlength="4">

      <label>Type</label>
      <div class="choice">
        <label><input type="radio" name="type" value="channels" checked> Serveur "salons" (texte + vocal, admins, plusieurs membres)</label>
        <label><input type="radio" name="type" value="mp"> Relais MP (demandes d'ami, MP + groupes)</label>
        <label><input type="radio" name="type" value="both"> Les deux à la fois (un seul nœud, apparaît dans MP et dans Salons)</label>
      </div>

      <label>Port d'écoute</label>
      <input name="port" type="number" value="25580" min="1" max="65535" required>

      <label>Salons texte initiaux (séparés par des virgules — ignoré si type "relais MP")</label>
      <input name="channels" value="general, hors-sujet">

      <label>Limite de caractères par message (100 à 10000)</label>
      <input name="maxMessageLength" type="number" value="5000" min="100" max="10000">

      <label style="margin-top:20px;display:flex;align-items:center;gap:8px;text-transform:none;cursor:pointer;">
        <input type="checkbox" name="serverListEnabled" value="1" checked style="width:auto;margin:0;">
        <span>Publier ce serveur sur l'annuaire central (serverListe.js)</span>
      </label>

      <label>URL de l'annuaire central</label>
      <input name="serverListUrl" value="http://msg.playnix.fr" placeholder="http://msg.playnix.fr">

      <label>Hôte ou IP publique annoncée (optionnel, détecté automatiquement si vide)</label>
      <input name="publicHost" placeholder="ex: mon-domaine.fr ou 82.64.x.x">

      <label>Description publique du serveur (optionnel)</label>
      <input name="description" placeholder="ex: Serveur de discussion convivial" maxlength="200">

      <button type="submit">Créer et démarrer</button>
    </form>
  </div>
</body></html>`;

  const srv = http.createServer((req,res)=>{
    if(req.method==='GET'){
      res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
      res.end(setupHtml);
      return;
    }
    if(req.method==='POST' && req.url==='/setup'){
      let body='';
      let tooBig = false;
      req.on('data', c=>{
        body += c;
        if(body.length > 20000){ tooBig = true; req.destroy(); }
      });
      req.on('end', ()=>{
        if(tooBig) return;
        try{
          const params = new URLSearchParams(body);
          const config = {
            name: (params.get('name')||'Serveur sans nom').slice(0,60),
            icon: (params.get('icon')||'').trim().slice(0,4) || null,
            type: ['mp','both'].includes(params.get('type')) ? params.get('type') : 'channels',
            port: Math.min(65535, Math.max(1, parseInt(params.get('port'),10) || 25580)),
            channels: (params.get('channels')||'general')
              .split(',').map(s=>s.trim().toLowerCase().replace(/\s+/g,'-')).filter(s=>s && !DANGEROUS_KEYS.has(s)).slice(0,20),
            maxMessageLength: Math.min(10000, Math.max(100, parseInt(params.get('maxMessageLength'),10) || 5000)),
            serverList: {
              enabled: params.get('serverListEnabled') === '1',
              url: (params.get('serverListUrl') || 'http://msg.playnix.fr').trim(),
              publicHost: (params.get('publicHost') || '').trim(),
              description: (params.get('description') || '').trim().slice(0, 200)
            }
          };
          fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
          res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
          res.end(`<body style="background:#0a0d13;color:#4fe0c4;font-family:sans-serif;
            display:flex;align-items:center;justify-content:center;height:100vh;">
            <div style="text-align:center">
              <h2>Configuration enregistrée ✓</h2>
              <p style="color:#7c8797">Ferme cette fenêtre, arrête ce processus (Ctrl+C) puis relance :<br><code>node server.js</code></p>
            </div></body>`);
          console.log('\n✓ Configuration enregistrée dans server-config.json');
          console.log('  Relance avec: node server.js\n');
          setTimeout(()=>process.exit(0), 800);
        }catch(e){
          res.writeHead(400, {'Content-Type':'text/plain; charset=utf-8'});
          res.end('Formulaire invalide.');
        }
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  srv.listen(SETUP_PORT, ()=>{
    console.log(`\nAucune configuration trouvée.`);
    console.log(`Ouvre http://localhost:${SETUP_PORT} dans ton navigateur pour régler ce serveur.\n`);
  });
}

/* ============================================================
   PERSISTANCE
   ============================================================ */
function loadOrInitData(config){
  if(fs.existsSync(DATA_PATH)){
    let d;
    try{ d = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8')); }
    catch(e){
      console.error(`\n✗ server-data.json est corrompu ou illisible (${e.message}).`);
      console.error(`  Répare/restaure ce fichier (ou supprime-le pour repartir de zéro — tu perdras l'historique) puis relance.\n`);
      process.exit(1);
    }
    if(typeof d !== 'object' || d === null) d = {};
    if(!d.channelMessages) d.channelMessages = {};
    if(!d.groups) d.groups = {};
    if(!d.groupMessages) d.groupMessages = {};
    if(d.icon === undefined) d.icon = config.icon || null;
    if(!d.voiceChannels) d.voiceChannels = ['Général'];
    if(!d.blocks) d.blocks = {};
    if(!d.owner) d.owner = null;
    if(!Array.isArray(d.admins)) d.admins = [];
    if(!Array.isArray(d.bans)) d.bans = [];
    if(!Array.isArray(d.channels)) d.channels = config.type!=='mp' ? ['general'] : [];
    if(!d.knownUsers) d.knownUsers = {};
    if(!d.friendships) d.friendships = {};
    if(!Array.isArray(d.friendRequests)) d.friendRequests = [];
    if(!Array.isArray(d.roles) || !d.roles.length){
      d.roles = [
        { id: 'admin', name: 'Administrateur', color: '#ff5c72', permissions: { manageServer:true, manageRoles:true, manageChannels:true, kick:true, ban:true }, channelPerms:{}, voicePerms:{} },
        { id: 'member', name: 'Membre', color: '#4fe0c4', permissions: {}, channelPerms:{}, voicePerms:{} }
      ];
    }
    if(!d.defaultRoleId) d.defaultRoleId = 'member';
    if(!d.userRoles) d.userRoles = {};
    if(!d.onboardingQuiz) d.onboardingQuiz = { enabled: false, title: "Questionnaire d'arrivée", description: "Réponds aux questions pour obtenir ton grade !", questions: [] };
    if(!d.quizCompleted) d.quizCompleted = {};
    for(const fp of Object.keys(d.knownUsers)){
      if(typeof d.knownUsers[fp] === 'string') d.knownUsers[fp] = { username: d.knownUsers[fp], avatar: null };
    }
    return d;
  }
  const data = {
    owner: null,
    admins: [],
    bans: [],
    icon: config.icon || null,
    channels: config.type!=='mp' ? (config.channels && config.channels.length ? config.channels : ['general']) : [],
    voiceChannels: config.type!=='mp' ? ['Général'] : [],
    channelMessages: {},
    knownUsers: {},
    friendships: {},
    friendRequests: [],
    blocks: {},
    groups: {},
    groupMessages: {},
    roles: [
      { id: 'admin', name: 'Administrateur', color: '#ff5c72', permissions: { manageServer:true, manageRoles:true, manageChannels:true, kick:true, ban:true }, channelPerms:{}, voicePerms:{} },
      { id: 'member', name: 'Membre', color: '#4fe0c4', permissions: {}, channelPerms:{}, voicePerms:{} }
    ],
    defaultRoleId: 'member',
    userRoles: {},
    onboardingQuiz: { enabled: false, title: "Questionnaire d'arrivée", description: "Réponds aux questions pour obtenir ton grade !", questions: [] },
    quizCompleted: {},
  };
  fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));
  return data;
}

/* ============================================================
   ÉTAPE 2 — config présente -> serveur relais WebSocket réel
   ============================================================ */
function runRelayServer(config){
  const data = loadOrInitData(config);
  function saveData(){
    try{ fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2)); }
    catch(e){ console.error('✗ Échec de sauvegarde de server-data.json :', e.message); }
  }

  const clients = new Map(); // clé: fp seul (serveur simple) ou "fp|type" (serveur "both") -> { socket, fp, connType, username, ... }
  const voiceChannelMembers = new Map();
  const groupVoiceMembers = new Map();
  const lastMsgAt = new Map();
  const lastActionAt = new Map();
  const ipConnCounts = new Map();

  /* ---------- Serveur "les deux à la fois" (salons + MP sur le même nœud) ----------
     Chaque connexion déclare, dès la poignée de main, dans quel mode elle se connecte
     (`wantType`). Sur un nœud "both", une même personne peut donc être connectée deux fois
     en parallèle (une socket "salons", une socket "MP") ; on les distingue via une clé
     composite dans `clients`. Sur un serveur à type unique, rien ne change : la clé reste
     simplement l'empreinte, comme avant. */
  function et(conn){ return config.type === 'both' ? (conn.wantType === 'mp' ? 'mp' : 'channels') : config.type; }
  function ckey(fp, type){ return config.type === 'both' ? fp + '|' + type : fp; }
  function isOnline(fp, type){ return clients.has(ckey(fp, type)); }
  function myClient(conn){ return clients.get(ckey(conn.fp, et(conn))); }
  function closeAllSessions(fp){ for(const [,c] of clients){ if(c.fp===fp){ try{ c.socket.end(); }catch(e){} } } }

  function str(v, maxLen){ return typeof v === 'string' ? v.trim().slice(0, maxLen) : ''; }
  function isDangerousKey(v){ return typeof v === 'string' && DANGEROUS_KEYS.has(v); }
  function hasDangerousField(msg){
    for(const field of KEY_LIKE_FIELDS){ if(isDangerousKey(msg[field])) return true; }
    return false;
  }
  function hasOwn(obj, key){ return typeof key === 'string' && Object.prototype.hasOwnProperty.call(obj, key); }
  function validPubJwk(jwk){
    return jwk && typeof jwk === 'object'
      && jwk.kty === 'EC' && jwk.crv === 'P-256'
      && typeof jwk.x === 'string' && jwk.x.length > 0 && jwk.x.length < 100
      && typeof jwk.y === 'string' && jwk.y.length > 0 && jwk.y.length < 100;
  }
  /* Un avatar doit être une image encodée en data: URL, jamais accepté tel quel : c'est une
     valeur qui sera renvoyée telle quelle à d'autres clients et insérée dans leur interface
     (attribut src d'une balise <img>). Sans validation stricte ici, un client modifié pourrait
     l'utiliser pour injecter du HTML/JS chez toute personne qui affiche son profil. */
  function safeAvatar(v){
    return (typeof v === 'string' && v.length < 60000 && /^data:image\/(png|jpe?g|gif|webp);base64,[A-Za-z0-9+/]+=*$/.test(v)) ? v : null;
  }
  function computeFingerprint(pubJwk){
    // Miroir exact de fingerprintOf() côté client : le serveur ne fait jamais
    // confiance à une empreinte fournie par le client, il la recalcule lui-même.
    const hash = nodeCrypto.createHash('sha256').update(JSON.stringify(pubJwk)).digest('hex');
    return hash.slice(0,16).match(/.{1,4}/g).join('-');
  }
  function actionThrottled(fp, action, minMs){
    const key = fp+':'+action;
    const now = Date.now();
    const last = lastActionAt.get(key) || 0;
    if(now - last < minMs) return true;
    lastActionAt.set(key, now);
    return false;
  }

  function frameEncode(str){
    const payload = Buffer.from(str, 'utf8');
    const len = payload.length;
    let header;
    if(len < 126){ header = Buffer.from([0x81, len]); }
    else if(len < 65536){ header = Buffer.alloc(4); header[0]=0x81; header[1]=126; header.writeUInt16BE(len,2); }
    else { header = Buffer.alloc(10); header[0]=0x81; header[1]=127; header.writeBigUInt64BE(BigInt(len),2); }
    return Buffer.concat([header, payload]);
  }
  function encodePong(payload){
    const len = payload.length;
    let header;
    if(len < 126){ header = Buffer.from([0x8A, len]); }
    else if(len < 65536){ header = Buffer.alloc(4); header[0]=0x8A; header[1]=126; header.writeUInt16BE(len,2); }
    else { header = Buffer.alloc(10); header[0]=0x8A; header[1]=127; header.writeBigUInt64BE(BigInt(len),2); }
    return Buffer.concat([header, payload]);
  }
  function tryParseFrame(buf){
    if(buf.length < 2) return null;
    const b0 = buf[0], b1 = buf[1];
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f, offset = 2;
    if(len === 126){
      if(buf.length < 4) return null;
      len = buf.readUInt16BE(2); offset = 4;
    } else if(len === 127){
      if(buf.length < 10) return null;
      const big = buf.readBigUInt64BE(2);
      if(big > BigInt(MAX_FRAME_BYTES)) return { tooLarge:true };
      len = Number(big); offset = 10;
    }
    if(len > MAX_FRAME_BYTES) return { tooLarge:true };
    if(masked && buf.length < offset+4) return null;
    const maskKey = masked ? buf.slice(offset, offset+4) : null;
    if(masked) offset += 4;
    if(buf.length < offset+len) return null;
    let payload = buf.slice(offset, offset+len);
    if(masked){
      const out = Buffer.alloc(len);
      for(let i=0;i<len;i++) out[i] = payload[i] ^ maskKey[i%4];
      payload = out;
    }
    return { opcode, payload, total: offset+len };
  }

  function send(socket, obj){ try{ socket.write(frameEncode(JSON.stringify(obj))); }catch(e){} }
  /* type: le mode visé ('channels'|'mp'). Omis = touche toutes les connexions de cette
     personne/de tout le monde quel que soit leur mode (utile pour une info vraiment globale
     au serveur, comme son icône). Sur un serveur à type unique, le paramètre est ignoré. */
  function sendTo(fp, obj, type){
    if(type){ const c = clients.get(ckey(fp, type)); if(c) send(c.socket, obj); return; }
    for(const [,c] of clients){ if(c.fp === fp) send(c.socket, obj); }
  }
  function broadcastExcept(exceptFp, obj, type){
    for(const [,c] of clients){ if((!type || c.connType===type) && c.fp !== exceptFp) send(c.socket, obj); }
  }
  function broadcastAll(obj, type){
    for(const [,c] of clients){ if(!type || c.connType===type) send(c.socket, obj); }
  }

  function rateLimited(fp){
    const now = Date.now();
    const last = lastMsgAt.get(fp) || 0;
    if(now - last < RATE_LIMIT_MS) return true;
    lastMsgAt.set(fp, now);
    return false;
  }

  function ciphertextTooLarge(ct){
    if(typeof ct !== 'string' || ct.length > 2500000) return true;
    return false;
  }

  function roleOf(fp){
    if(fp === data.owner) return 'owner';
    if(data.admins && data.admins.includes(fp)) return 'admin';
    return 'member';
  }

  function getUserRoleIds(fp){
    if(fp === data.owner) return ['owner'];
    const assigned = (data.userRoles && data.userRoles[fp]) || [];
    if(assigned.length > 0) return assigned;
    if(data.admins && data.admins.includes(fp)) return ['admin'];
    return [data.defaultRoleId || 'member'];
  }

  function getRolesDataForUser(fp){
    if(fp === data.owner){
      return [{ id: 'owner', name: 'Fondateur', color: '#ff7a45', isOwner: true }];
    }
    const roleIds = getUserRoleIds(fp);
    return roleIds.map(id => {
      const r = (data.roles || []).find(x => x.id === id);
      return r || { id, name: id === 'admin' ? 'Administrateur' : 'Membre', color: id === 'admin' ? '#ff5c72' : '#4fe0c4' };
    });
  }

  function isStaff(fp){
    if(fp === data.owner || (data.admins && data.admins.includes(fp))) return true;
    const roleIds = getUserRoleIds(fp);
    const roles = (data.roles || []).filter(r => roleIds.includes(r.id));
    return roles.some(r => r.permissions && (r.permissions.manageServer || r.permissions.manageRoles || r.permissions.manageChannels));
  }

  function canViewChannel(fp, channel){
    if(fp === data.owner) return true;
    if(data.admins && data.admins.includes(fp)) return true;
    const roleIds = getUserRoleIds(fp);
    const roles = (data.roles || []).filter(r => roleIds.includes(r.id));
    if(roles.some(r => r.permissions && (r.permissions.manageServer || r.permissions.manageRoles || r.permissions.manageChannels))) return true;
    return roles.some(r => {
      if(r.channelPerms && r.channelPerms[channel] && r.channelPerms[channel].view !== undefined){
        return !!r.channelPerms[channel].view;
      }
      if(!r.permissions) return true;
      if(r.permissions.viewChannels === true || r.permissions.viewChannels === undefined) return true;
      if(Array.isArray(r.permissions.viewChannels)) return r.permissions.viewChannels.includes(channel);
      return false;
    });
  }

  function canWriteChannel(fp, channel){
    if(fp === data.owner) return true;
    if(data.admins && data.admins.includes(fp)) return true;
    const roleIds = getUserRoleIds(fp);
    const roles = (data.roles || []).filter(r => roleIds.includes(r.id));
    if(roles.some(r => r.permissions && (r.permissions.manageServer || r.permissions.manageRoles || r.permissions.manageChannels))) return true;
    return roles.some(r => {
      if(r.channelPerms && r.channelPerms[channel] && r.channelPerms[channel].write !== undefined){
        return !!r.channelPerms[channel].write;
      }
      if(!r.permissions) return true;
      if(r.permissions.writeChannels === true || r.permissions.writeChannels === undefined) return true;
      if(Array.isArray(r.permissions.writeChannels)) return r.permissions.writeChannels.includes(channel);
      return false;
    });
  }

  function canConnectVoice(fp, voiceChannel){
    if(fp === data.owner) return true;
    if(data.admins && data.admins.includes(fp)) return true;
    const roleIds = getUserRoleIds(fp);
    const roles = (data.roles || []).filter(r => roleIds.includes(r.id));
    if(roles.some(r => r.permissions && (r.permissions.manageServer || r.permissions.manageRoles || r.permissions.manageChannels))) return true;
    return roles.some(r => {
      if(r.voicePerms && r.voicePerms[voiceChannel] && r.voicePerms[voiceChannel].connect !== undefined){
        return !!r.voicePerms[voiceChannel].connect;
      }
      if(!r.permissions) return true;
      if(r.permissions.connectVoice === true || r.permissions.connectVoice === undefined) return true;
      if(Array.isArray(r.permissions.connectVoice)) return r.permissions.connectVoice.includes(voiceChannel);
      return false;
    });
  }

  function canManageRoles(fp){
    if(fp === data.owner || (data.admins && data.admins.includes(fp))) return true;
    const roleIds = getUserRoleIds(fp);
    const roles = (data.roles || []).filter(r => roleIds.includes(r.id));
    return roles.some(r => r.permissions && (r.permissions.manageRoles || r.permissions.manageServer));
  }

  function canManageChannels(fp){
    if(fp === data.owner || (data.admins && data.admins.includes(fp))) return true;
    const roleIds = getUserRoleIds(fp);
    const roles = (data.roles || []).filter(r => roleIds.includes(r.id));
    return roles.some(r => r.permissions && (r.permissions.manageChannels || r.permissions.manageServer));
  }

  function rosterList(){
    return [...clients.values()].filter(c=>c.connType==='channels').map(c=>({
      fingerprint: c.fp, username: c.username, pubJwk: c.pubJwk, avatar: c.avatar||null,
      bio: c.bio||'', shareServerList: c.shareServerList!==false, hiddenServers: c.hiddenServers||[],
      role: roleOf(c.fp),
      roles: getRolesDataForUser(c.fp),
      roleIds: getUserRoleIds(c.fp),
    }));
  }

  function cleanup(fp, socket, type){
    if(!fp) return;
    const key = ckey(fp, type||'channels');
    const entry = clients.get(key);
    if(!entry) return;
    // si l'identité s'est reconnectée entre-temps (nouvelle socket déjà enregistrée), ne pas
    // supprimer la nouvelle connexion à cause de la fermeture tardive de l'ancienne
    if(socket && entry.socket !== socket) return;
    clients.delete(key);
    for(const [chan, members] of voiceChannelMembers){
      if(members.delete(fp)) broadcastAll({ t:'voice-channel-roster', channel: chan, members:[...members] }, 'channels');
    }
    for(const [gid, members] of groupVoiceMembers){
      if(members.delete(fp)){
        const group = data.groups[gid];
        if(group) for(const m of group.members) sendTo(m, { t:'group-voice-roster', groupId: gid, members:[...members] }, 'mp');
      }
    }
    if(entry.connType === 'channels') broadcastExcept(fp, { t:'peer-leave', fingerprint: fp }, 'channels');
    if(entry.connType === 'mp'){
      const notifyFps = new Set(data.friendships[fp] || []);
      for(const g of Object.values(data.groups || {})){
        if(g.members && g.members.includes(fp)){
          for(const m of g.members){
            if(m !== fp) notifyFps.add(m);
          }
        }
      }
      for(const target of notifyFps){
        sendTo(target, { t:'friend-offline', fingerprint: fp }, 'mp');
      }
    }
    console.log(`- ${fp} déconnecté [${entry.connType}] (${clients.size} en ligne)`);
  }

  function isFriend(a, b){ return (data.friendships[a]||[]).includes(b); }
  function isBlocked(a, b){ return (data.blocks[a]||[]).includes(b); }
  function removeFriendship(a, b){
    if(data.friendships[a]) data.friendships[a] = data.friendships[a].filter(x=>x!==b);
    if(data.friendships[b]) data.friendships[b] = data.friendships[b].filter(x=>x!==a);
  }
  function addFriendship(a, b){
    if(!data.friendships[a]) data.friendships[a] = [];
    if(!data.friendships[b]) data.friendships[b] = [];
    if(!data.friendships[a].includes(b)) data.friendships[a].push(b);
    if(!data.friendships[b].includes(a)) data.friendships[b].push(a);
  }
  function friendListFor(fp){
    return (data.friendships[fp]||[]).map(f=>({
      fingerprint:f, username: (data.knownUsers[f]||{}).username||'?',
      pubJwk:(data.knownUsers[f]||{}).pubJwk||null, avatar:(data.knownUsers[f]||{}).avatar||null,
      bio: (data.knownUsers[f]||{}).bio||'', shareServerList: (data.knownUsers[f]||{}).shareServerList!==false,
      hiddenServers: (data.knownUsers[f]||{}).hiddenServers||[],
      online: isOnline(f, 'mp'),
    }));
  }
  function blockedListFor(fp){
    return (data.blocks[fp]||[]).map(f=>({ fingerprint:f, username:(data.knownUsers[f]||{}).username||'?' }));
  }
  function incomingRequestsFor(fp){ return data.friendRequests.filter(r=>r.to===fp); }
  function outgoingRequestsFor(fp){ return data.friendRequests.filter(r=>r.from===fp); }
  function groupPayload(g){
    return { id:g.id, name:g.name, createdBy:g.createdBy,
      members: g.members.map(m=>({ fingerprint:m, username:(data.knownUsers[m]||{}).username||'?', avatar:(data.knownUsers[m]||{}).avatar||null, pubJwk:(data.knownUsers[m]||{}).pubJwk||null, online: isOnline(m, 'mp') })) };
  }
  function groupsFor(fp){
    return Object.values(data.groups).filter(g=>g.members.includes(fp)).map(groupPayload);
  }

  async function finalizeAuth(conn, socket, pa){
    const { fp, username, avatar, bio, shareServerList, hiddenServers, pubJwk } = pa;
    conn.wantType = pa.wantType;
    const myType = et(conn);
    const key = ckey(fp, myType);
    const previous = clients.get(key);
    if(previous && previous.socket !== socket){
      // la même identité se reconnecte dans le même mode (nouvel onglet, reprise réseau...) :
      // on ferme proprement l'ancienne connexion au lieu de la laisser traîner
      try{ previous.socket.end(); }catch(e){}
    }
    conn.fp = fp;
    conn.authenticated = true;
    clients.set(key, { socket, fp, connType: myType, username, pubJwk, avatar, bio, shareServerList, hiddenServers });
    data.knownUsers[fp] = { username, pubJwk, avatar, bio, shareServerList, hiddenServers };
    if(!data.owner) data.owner = fp; // le premier arrivé devient "hôte" du serveur, salons comme MP (peut définir l'icône, etc.)
    if(myType === 'channels'){
      if(!data.userRoles[fp]){
        data.userRoles[fp] = fp === data.owner ? ['owner'] : [data.defaultRoleId || 'member'];
      }
    }
    saveData();

    const dualMode = config.type === 'both';
    if(myType === 'channels'){
      send(socket, {
        t:'welcome', serverName: config.name, serverType: 'channels', icon: data.icon, dualMode,
        channels: data.channels, voiceChannels: data.voiceChannels,
        roster: rosterList().filter(r=>r.fingerprint!==fp),
        role: roleOf(fp), maxMessageLength: config.maxMessageLength,
        roles: data.roles || [], defaultRoleId: data.defaultRoleId || 'member',
        userRoles: data.userRoles || {}, onboardingQuiz: data.onboardingQuiz || null,
        myRoles: getRolesDataForUser(fp), myRoleIds: getUserRoleIds(fp),
        quizCompleted: !!(data.quizCompleted && data.quizCompleted[fp]),
        voiceChannelRoster: Object.fromEntries([...voiceChannelMembers.entries()].map(([k,v])=>[k,[...v]])),
      });
      broadcastExcept(fp, { t:'peer-join', fingerprint: fp, username, pubJwk, avatar, bio, shareServerList, hiddenServers, role: roleOf(fp), roles: getRolesDataForUser(fp), roleIds: getUserRoleIds(fp) }, 'channels');
      if(data.onboardingQuiz && data.onboardingQuiz.enabled && data.onboardingQuiz.questions && data.onboardingQuiz.questions.length > 0 && !(data.quizCompleted && data.quizCompleted[fp]) && fp !== data.owner){
        send(socket, { t:'onboarding-quiz-required', quiz: data.onboardingQuiz });
      }
    } else {
      const myGroups = groupsFor(fp);
      send(socket, {
        t:'welcome', serverName: config.name, serverType: 'mp', icon: data.icon, role: roleOf(fp), dualMode,
        friends: friendListFor(fp),
        incoming: incomingRequestsFor(fp),
        outgoing: outgoingRequestsFor(fp),
        groups: myGroups,
        blocked: blockedListFor(fp),
        maxMessageLength: config.maxMessageLength,
        groupVoiceRoster: Object.fromEntries(myGroups.map(g=>[g.id, [...(groupVoiceMembers.get(g.id)||[])]])),
      });
      const notifyFps = new Set(data.friendships[fp] || []);
      for(const g of Object.values(data.groups || {})){
        if(g.members && g.members.includes(fp)){
          for(const m of g.members){
            if(m !== fp) notifyFps.add(m);
          }
        }
      }
      for(const target of notifyFps){
        sendTo(target, { t:'friend-online', fingerprint: fp, username }, 'mp');
      }
    }
    console.log(`+ ${username} (${fp}) authentifié [${myType}] (${clients.size} en ligne)`);
  }

  async function handleHelloInit(conn, socket, msg){
    if(conn.authenticated || conn.pendingAuth) return;
    const username = str(msg.username, 32);
    if(!username) return;
    if(!validPubJwk(msg.pubJwk)) return;

    let fp;
    try{ fp = computeFingerprint(msg.pubJwk); }catch(e){ return; }

    if(data.bans.includes(fp)){ send(socket, { t:'banned' }); socket.end(); return; }

    const normalizedName = username.toLocaleLowerCase('fr-FR');
    const usedByAnotherIdentity = Object.entries(data.knownUsers).some(([knownFp, user])=>
      knownFp !== fp && user.username && user.username.trim().toLocaleLowerCase('fr-FR') === normalizedName
    );
    if(usedByAnotherIdentity){ send(socket, { t:'username-taken', username }); socket.end(); return; }

    const avatar = safeAvatar(msg.avatar);
    const bio = str(msg.bio, 200);
    const shareServerList = msg.shareServerList !== false;
    const hiddenServers = Array.isArray(msg.hiddenServers) ? msg.hiddenServers.filter(x=>typeof x==='string' && x.length<=120).slice(0,100) : [];

    let serverKeyPair, clientPubKey, serverEphemeralPubJwk;
    try{
      serverKeyPair = await subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveBits']);
      clientPubKey = await subtle.importKey('jwk', msg.pubJwk, {name:'ECDH', namedCurve:'P-256'}, false, []);
      serverEphemeralPubJwk = await subtle.exportKey('jwk', serverKeyPair.publicKey);
    }catch(e){ try{ socket.destroy(); }catch(e2){} return; }

    const nonce = nodeCrypto.randomBytes(24);
    conn.pendingAuth = {
      fp, username, avatar, bio, shareServerList, hiddenServers, pubJwk: msg.pubJwk,
      wantType: (msg.wantType === 'mp' || msg.wantType === 'channels') ? msg.wantType : 'channels',
      nonce, serverPrivateKey: serverKeyPair.privateKey, clientPubKey,
      timeout: setTimeout(()=>{ try{ socket.destroy(); }catch(e){} }, AUTH_TIMEOUT_MS),
    };
    send(socket, { t:'auth-challenge', nonce: nonce.toString('base64'), serverEphemeralPub: serverEphemeralPubJwk });
  }

  async function handleAuthResponse(conn, socket, msg){
    const pa = conn.pendingAuth;
    if(!pa) return;
    clearTimeout(pa.timeout);
    conn.pendingAuth = null;
    let ok = false;
    try{
      const bits = await subtle.deriveBits({name:'ECDH', public: pa.clientPubKey}, pa.serverPrivateKey, 256);
      const hmacKey = await subtle.importKey('raw', bits, {name:'HMAC', hash:'SHA-256'}, false, ['verify']);
      const proofBuf = Buffer.from(typeof msg.proof === 'string' ? msg.proof : '', 'base64');
      ok = await subtle.verify('HMAC', hmacKey, proofBuf, pa.nonce);
    }catch(e){ ok = false; }
    if(!ok){ send(socket, { t:'auth-failed' }); try{ socket.destroy(); }catch(e){} return; }
    await finalizeAuth(conn, socket, pa);
  }

  async function handleMessage(conn, socket, msg){
    if(!msg || typeof msg !== 'object' || typeof msg.t !== 'string') return;
    if(hasDangerousField(msg)) return;

    if(msg.t === 'hello-init'){ await handleHelloInit(conn, socket, msg); return; }
    if(msg.t === 'auth-response'){ await handleAuthResponse(conn, socket, msg); return; }
    if(!conn.authenticated) return;
    const myFingerprint = conn.fp;

    /* ===== PROFIL ===== */
    if(msg.t === 'update-profile'){
      if(actionThrottled(myFingerprint, 'update-profile', 500)) return;
      const bio = str(msg.bio, 200);
      const shareServerList = msg.shareServerList !== false;
      const hiddenServers = Array.isArray(msg.hiddenServers) ? msg.hiddenServers.filter(x=>typeof x==='string' && x.length<=120).slice(0,100) : [];
      const existing = myClient(conn);
      const avatar = (msg.avatar === undefined) ? (existing ? existing.avatar : null) : safeAvatar(msg.avatar);
      // met à jour TOUTES les sessions de cette personne (sur un nœud "both" elle peut être
      // connectée à la fois en mode salons et en mode MP) : le profil est partagé, pas par mode.
      for(const [,c] of clients){ if(c.fp === myFingerprint){ c.bio = bio; c.shareServerList = shareServerList; c.hiddenServers = hiddenServers; c.avatar = avatar; } }
      if(data.knownUsers[myFingerprint]) Object.assign(data.knownUsers[myFingerprint], { bio, shareServerList, hiddenServers, avatar });
      saveData();
      broadcastExcept(myFingerprint, { t:'peer-profile-update', fingerprint: myFingerprint, bio, shareServerList, hiddenServers, avatar }, 'channels');
      for(const f of (data.friendships[myFingerprint]||[])) sendTo(f, { t:'peer-profile-update', fingerprint: myFingerprint, bio, shareServerList, hiddenServers, avatar }, 'mp');
      return;
    }

    /* ===== RELAIS CIBLÉ ===== */
    if(msg.t === 'relay'){
      if(typeof msg.to !== 'string' || !msg.payload || typeof msg.payload !== 'object') return;
      const tempId = (typeof msg.payload.tempId === 'string') ? msg.payload.tempId.slice(0,64) : undefined;
      if(et(conn) === 'mp' && msg.payload.kind === 'chat'){
        if(!isFriend(myFingerprint, msg.to)){
          send(socket, { t:'error', message:"Vous n'êtes pas ami avec cet utilisateur.", tempId });
          return;
        }
        if(isBlocked(msg.to, myFingerprint) || isBlocked(myFingerprint, msg.to)) return; // rejet silencieux (ne révèle pas le blocage)
        if(ciphertextTooLarge(msg.payload.ct)){ send(socket, { t:'error', message:`Message trop long (max ~${config.maxMessageLength} caractères).`, tempId }); return; }
        if(rateLimited(myFingerprint)){ send(socket, { t:'rate-limited', tempId }); return; }
      }
      if(et(conn) === 'mp' && msg.payload.kind !== 'chat'){
        // appels, signalisation WebRTC, transmission de clé de groupe : réservé aux amis ou aux
        // co-membres d'un groupe commun (jamais à un parfait inconnu) — bloque le spam d'appel /
        // la signalisation WebRTC non sollicitée depuis un compte avec qui on n'a aucun lien.
        const related = isFriend(myFingerprint, msg.to) ||
          Object.values(data.groups).some(g=> g.members.includes(myFingerprint) && g.members.includes(msg.to));
        if(!related) return;
        if(isBlocked(msg.to, myFingerprint) || isBlocked(myFingerprint, msg.to)) return;
      }
      const target = clients.get(ckey(msg.to, et(conn))); // reste dans le même mode que l'expéditeur (salons <-> salons, MP <-> MP)
      if(target){
        send(target.socket, { t:'relay', from: myFingerprint, payload: msg.payload });
        if(msg.payload.kind === 'chat' && tempId) send(socket, { t:'relay-ack', tempId }); // confirme la remise (le destinataire est en ligne)
      }
      // si le destinataire n'est pas en ligne, on ne renvoie rien : le client détectera l'absence
      // d'accusé via son propre délai d'attente (pas de file d'attente pour les MP, par design)
      return;
    }
    if(msg.t === 'relay-all'){
      if(actionThrottled(myFingerprint, 'relay-all', 300)) return;
      broadcastExcept(myFingerprint, { t:'relay', from: myFingerprint, payload: msg.payload }, et(conn));
      return;
    }

    /* ===== SALONS ===== */
    if(msg.t === 'channel-message' && et(conn)==='channels'){
      if(typeof msg.channel !== 'string' || !data.channels.includes(msg.channel)) return;
      const tempId = (typeof msg.tempId === 'string') ? msg.tempId.slice(0,64) : undefined;
      if(!canWriteChannel(myFingerprint, msg.channel)){
        send(socket, { t:'error', message: "Tu n'as pas la permission d'écrire dans ce salon.", tempId });
        return;
      }
      if(rateLimited(myFingerprint)){ send(socket, { t:'rate-limited', scope:'channel', scopeId: msg.channel, tempId }); return; }
      if(ciphertextTooLarge(msg.ct) || typeof msg.iv !== 'string'){ send(socket, { t:'error', message:`Message trop long.`, tempId }); return; }
      const id = 'm_'+nodeCrypto.randomBytes(8).toString('hex');
      const entry = { id, from: myFingerprint, iv: msg.iv, ct: msg.ct, ts: Date.now() };
      if(!data.channelMessages[msg.channel]) data.channelMessages[msg.channel] = [];
      data.channelMessages[msg.channel].push(entry);
      if(data.channelMessages[msg.channel].length > MAX_HISTORY) data.channelMessages[msg.channel].shift();
      saveData();
      send(socket, { t:'channel-message-ack', channel: msg.channel, id, ts: entry.ts, tempId });
      for(const [,c] of clients){
        if(c.connType==='channels' && c.fp !== myFingerprint && canViewChannel(c.fp, msg.channel)){
          send(c.socket, { t:'channel-relay', channel: msg.channel, id, from: myFingerprint, iv: msg.iv, ct: msg.ct, ts: entry.ts });
        }
      }
      return;
    }
    if(msg.t === 'get-channel-history' && et(conn)==='channels'){
      if(typeof msg.channel !== 'string' || !data.channels.includes(msg.channel)) return;
      if(!canViewChannel(myFingerprint, msg.channel)){
        send(socket, { t:'error', message: "Tu n'as pas la permission d'accéder à ce salon." });
        return;
      }
      send(socket, { t:'channel-history', channel: msg.channel, messages: data.channelMessages[msg.channel]||[] });
      return;
    }
    if(msg.t === 'submit-onboarding-quiz' && et(conn)==='channels'){
      if(actionThrottled(myFingerprint, 'submit-quiz', 300)) return;
      const answers = Array.isArray(msg.answers) ? msg.answers : [];
      const assigned = new Set();
      for(const ans of answers){
        if(ans && typeof ans.roleId === 'string' && data.roles.find(r=>r.id === ans.roleId)){
          assigned.add(ans.roleId);
        }
      }
      if(assigned.size === 0 && data.defaultRoleId) assigned.add(data.defaultRoleId);
      data.userRoles[myFingerprint] = [...assigned];
      if(!data.quizCompleted) data.quizCompleted = {};
      data.quizCompleted[myFingerprint] = true;
      saveData();
      send(socket, { t:'onboarding-quiz-complete', assignedRoles: [...assigned] });
      broadcastAll({ t:'peer-role-update', fingerprint: myFingerprint, role: roleOf(myFingerprint), roles: getRolesDataForUser(myFingerprint), roleIds: getUserRoleIds(myFingerprint) }, 'channels');
      return;
    }
    if(msg.t === 'edit-message' && msg.scope==='channel' && et(conn)==='channels'){
      if(typeof msg.scopeId !== 'string') return;
      const list = data.channelMessages[msg.scopeId]||[];
      const entry = list.find(e=>e.id===msg.id);
      if(!entry || entry.deleted) return;
      if(entry.from !== myFingerprint) return;
      if(ciphertextTooLarge(msg.ct) || typeof msg.iv !== 'string'){ send(socket, { t:'error', message:`Message trop long.` }); return; }
      entry.iv = msg.iv; entry.ct = msg.ct; entry.editedTs = Date.now();
      saveData();
      broadcastAll({ t:'message-edited', scope:'channel', scopeId: msg.scopeId, id: msg.id, iv: msg.iv, ct: msg.ct, editedTs: entry.editedTs }, 'channels');
      return;
    }
    if(msg.t === 'delete-message' && msg.scope==='channel' && et(conn)==='channels'){
      if(typeof msg.scopeId !== 'string') return;
      const list = data.channelMessages[msg.scopeId]||[];
      const entry = list.find(e=>e.id===msg.id);
      if(!entry) return;
      const allowed = entry.from === myFingerprint || isStaff(myFingerprint);
      if(!allowed) return;
      entry.deleted = true; entry.iv = null; entry.ct = null;
      saveData();
      broadcastAll({ t:'message-deleted', scope:'channel', scopeId: msg.scopeId, id: msg.id }, 'channels');
      return;
    }

    /* ===== SALONS VOCAUX ===== */
    if(msg.t === 'join-voice-channel' && et(conn)==='channels'){
      if(typeof msg.channel !== 'string' || !data.voiceChannels.includes(msg.channel)) return;
      if(!canConnectVoice(myFingerprint, msg.channel)){
        send(socket, { t:'error', message: "Tu n'as pas la permission d'accéder à ce salon vocal." });
        return;
      }
      for(const [chan, members] of voiceChannelMembers){
        if(members.has(myFingerprint) && chan!==msg.channel){ members.delete(myFingerprint); broadcastAll({ t:'voice-channel-roster', channel:chan, members:[...members] }, 'channels'); }
      }
      if(!voiceChannelMembers.has(msg.channel)) voiceChannelMembers.set(msg.channel, new Set());
      voiceChannelMembers.get(msg.channel).add(myFingerprint);
      broadcastAll({ t:'voice-channel-roster', channel: msg.channel, members:[...voiceChannelMembers.get(msg.channel)] }, 'channels');
      return;
    }
    if(msg.t === 'leave-voice-channel' && et(conn)==='channels'){
      if(typeof msg.channel !== 'string') return;
      const members = voiceChannelMembers.get(msg.channel);
      if(members){ members.delete(myFingerprint); broadcastAll({ t:'voice-channel-roster', channel: msg.channel, members:[...members] }, 'channels'); }
      return;
    }

    /* ===== ADMINISTRATION (serveurs "channels") ===== */
    /* ===== ICÔNE DE SERVEUR — pour les relais MP aussi, réservé à l'hôte (premier arrivé) ===== */
    if(msg.t === 'admin-action' && msg.action === 'set-icon'){
      if(actionThrottled(myFingerprint, 'admin-action', 200)) return;
      if(!isStaff(myFingerprint)) return;
      data.icon = str(msg.icon, 4) || null; saveData();
      broadcastAll({ t:'server-info-update', name: config.name, icon: data.icon }); // touche tous les modes (icône partagée)
      return;
    }

    if(msg.t === 'admin-action' && config.type !== 'mp'){
      if(actionThrottled(myFingerprint, 'admin-action', 200)) return;
      const staff = isStaff(myFingerprint);
      const isOwner = myFingerprint === data.owner;
      const canRoles = canManageRoles(myFingerprint);
      const canChans = canManageChannels(myFingerprint);
      if(msg.action === 'create-channel' && canChans){
        const name = str(msg.name, 32).toLowerCase().replace(/\s+/g,'-');
        if(name && !DANGEROUS_KEYS.has(name) && !data.channels.includes(name) && data.channels.length < 50){
          data.channels.push(name); data.channelMessages[name]=[]; saveData();
          broadcastAll({ t:'channels-update', channels: data.channels }, 'channels');
        }
      } else if(msg.action === 'delete-channel' && canChans){
        if(typeof msg.name === 'string' && data.channels.length > 1){
          data.channels = data.channels.filter(c=>c!==msg.name);
          delete data.channelMessages[msg.name];
          saveData();
          broadcastAll({ t:'channels-update', channels: data.channels }, 'channels');
        }
      } else if(msg.action === 'create-voice-channel' && canChans){
        const name = str(msg.name, 32);
        if(name && !DANGEROUS_KEYS.has(name) && !data.voiceChannels.includes(name) && data.voiceChannels.length < 50){
          data.voiceChannels.push(name); saveData();
          broadcastAll({ t:'voice-channels-update', voiceChannels: data.voiceChannels }, 'channels');
        }
      } else if(msg.action === 'delete-voice-channel' && canChans){
        if(typeof msg.name === 'string' && data.voiceChannels.length > 1){
          data.voiceChannels = data.voiceChannels.filter(c=>c!==msg.name);
          voiceChannelMembers.delete(msg.name);
          saveData();
          broadcastAll({ t:'voice-channels-update', voiceChannels: data.voiceChannels }, 'channels');
        }
      } else if(msg.action === 'kick' && staff && typeof msg.target === 'string' && msg.target !== data.owner){
        sendTo(msg.target, { t:'kicked', by: myClient(conn)?.username });
        closeAllSessions(msg.target);
      } else if(msg.action === 'ban' && staff && typeof msg.target === 'string' && msg.target !== data.owner){
        if(!data.bans.includes(msg.target)) data.bans.push(msg.target);
        saveData();
        sendTo(msg.target, { t:'banned' });
        closeAllSessions(msg.target);
      } else if(msg.action === 'unban' && staff && typeof msg.target === 'string'){
        data.bans = data.bans.filter(b=>b!==msg.target); saveData();
      } else if(msg.action === 'create-role' && canRoles){
        const name = str(msg.name, 32) || 'Nouveau rôle';
        const color = str(msg.color, 16) || '#4fe0c4';
        const id = 'r_' + nodeCrypto.randomBytes(4).toString('hex');
        const role = { id, name, color, permissions: msg.permissions || {}, channelPerms: msg.channelPerms || {}, voicePerms: msg.voicePerms || {} };
        data.roles.push(role);
        saveData();
        broadcastAll({ t:'roles-update', roles: data.roles, defaultRoleId: data.defaultRoleId, userRoles: data.userRoles }, 'channels');
      } else if(msg.action === 'edit-role' && canRoles){
        const role = data.roles.find(r => r.id === msg.roleId);
        if(role){
          if(typeof msg.name === 'string') role.name = str(msg.name, 32) || role.name;
          if(typeof msg.color === 'string') role.color = str(msg.color, 16) || role.color;
          if(msg.permissions && typeof msg.permissions === 'object') role.permissions = msg.permissions;
          if(msg.channelPerms && typeof msg.channelPerms === 'object') role.channelPerms = msg.channelPerms;
          if(msg.voicePerms && typeof msg.voicePerms === 'object') role.voicePerms = msg.voicePerms;
          saveData();
          broadcastAll({ t:'roles-update', roles: data.roles, defaultRoleId: data.defaultRoleId, userRoles: data.userRoles }, 'channels');
        }
      } else if(msg.action === 'delete-role' && canRoles){
        if(msg.roleId && msg.roleId !== 'admin' && msg.roleId !== 'member'){
          data.roles = data.roles.filter(r => r.id !== msg.roleId);
          for(const [fp, rids] of Object.entries(data.userRoles)){
            data.userRoles[fp] = rids.filter(id => id !== msg.roleId);
          }
          if(data.defaultRoleId === msg.roleId) data.defaultRoleId = 'member';
          saveData();
          broadcastAll({ t:'roles-update', roles: data.roles, defaultRoleId: data.defaultRoleId, userRoles: data.userRoles }, 'channels');
        }
      } else if(msg.action === 'set-default-role' && canRoles){
        if(typeof msg.roleId === 'string' && data.roles.find(r => r.id === msg.roleId)){
          data.defaultRoleId = msg.roleId;
          saveData();
          broadcastAll({ t:'roles-update', roles: data.roles, defaultRoleId: data.defaultRoleId, userRoles: data.userRoles }, 'channels');
        }
      } else if(msg.action === 'assign-user-role' && canRoles){
        if(typeof msg.target === 'string' && msg.target !== data.owner){
          const current = new Set(data.userRoles[msg.target] || [data.defaultRoleId || 'member']);
          if(msg.add && typeof msg.roleId === 'string') current.add(msg.roleId);
          else if(!msg.add && typeof msg.roleId === 'string') current.delete(msg.roleId);
          data.userRoles[msg.target] = [...current];
          if(data.userRoles[msg.target].includes('admin')){
            if(!data.admins.includes(msg.target)) data.admins.push(msg.target);
          } else {
            data.admins = data.admins.filter(a => a !== msg.target);
          }
          saveData();
          broadcastAll({ t:'peer-role-update', fingerprint: msg.target, role: roleOf(msg.target), roles: getRolesDataForUser(msg.target), roleIds: getUserRoleIds(msg.target) }, 'channels');
          broadcastAll({ t:'roles-update', roles: data.roles, defaultRoleId: data.defaultRoleId, userRoles: data.userRoles }, 'channels');
        }
      } else if(msg.action === 'set-onboarding-quiz' && canRoles){
        if(msg.quiz && typeof msg.quiz === 'object'){
          data.onboardingQuiz = {
            enabled: !!msg.quiz.enabled,
            title: str(msg.quiz.title, 60) || "Questionnaire d'arrivée",
            description: str(msg.quiz.description, 200) || "",
            questions: Array.isArray(msg.quiz.questions) ? msg.quiz.questions.slice(0, 10).map(q => ({
              id: q.id || ('q_' + Math.random().toString(36).slice(2, 7)),
              question: str(q.question, 120),
              options: Array.isArray(q.options) ? q.options.slice(0, 6).map(o => ({ text: str(o.text, 60), roleId: str(o.roleId, 32) })) : []
            })) : []
          };
          saveData();
          broadcastAll({ t:'roles-update', roles: data.roles, defaultRoleId: data.defaultRoleId, userRoles: data.userRoles, onboardingQuiz: data.onboardingQuiz }, 'channels');
        }
      } else if(msg.action === 'promote' && isOwner && typeof msg.target === 'string'){
        if(!data.admins.includes(msg.target)) data.admins.push(msg.target);
        if(!data.userRoles[msg.target]) data.userRoles[msg.target] = [];
        if(!data.userRoles[msg.target].includes('admin')) data.userRoles[msg.target].push('admin');
        saveData();
        broadcastAll({ t:'peer-role-update', fingerprint: msg.target, role: roleOf(msg.target), roles: getRolesDataForUser(msg.target), roleIds: getUserRoleIds(msg.target) }, 'channels');
      } else if(msg.action === 'demote' && isOwner && typeof msg.target === 'string'){
        data.admins = data.admins.filter(a=>a!==msg.target);
        if(data.userRoles[msg.target]) data.userRoles[msg.target] = data.userRoles[msg.target].filter(r => r !== 'admin');
        saveData();
        broadcastAll({ t:'peer-role-update', fingerprint: msg.target, role: roleOf(msg.target), roles: getRolesDataForUser(msg.target), roleIds: getUserRoleIds(msg.target) }, 'channels');
      }
      return;
    }

    /* ===== AMIS ===== */
    if(msg.t === 'search-user' && et(conn)==='mp'){
      if(actionThrottled(myFingerprint, 'search-user', 400)) return;
      const q = str(msg.query, 60).toLowerCase();
      const results = Object.entries(data.knownUsers)
        .filter(([fp,u])=> fp!==myFingerprint && u.username && u.username.toLowerCase().includes(q) && !isBlocked(fp, myFingerprint) && !isBlocked(myFingerprint, fp))
        .slice(0,10)
        .map(([fp,u])=>({ fingerprint: fp, username: u.username, avatar: u.avatar||null, online: isOnline(fp, 'mp'), alreadyFriend: isFriend(myFingerprint,fp) }));
      send(socket, { t:'search-results', results });
      return;
    }
    if(msg.t === 'friend-request' && et(conn)==='mp'){
      if(actionThrottled(myFingerprint, 'friend-request', 400)) return;
      const to = msg.to;
      if(typeof to !== 'string' || to===myFingerprint || isFriend(myFingerprint,to)) return;
      if(isBlocked(to, myFingerprint) || isBlocked(myFingerprint, to)) return;
      if(data.friendRequests.find(r=>r.from===myFingerprint && r.to===to)) return;
      if(outgoingRequestsFor(myFingerprint).length >= 200) return;
      const req = { from: myFingerprint, to, fromUsername: myClient(conn).username, toUsername: (data.knownUsers[to]||{}).username||'?', ts: Date.now() };
      data.friendRequests.push(req); saveData();
      sendTo(to, { t:'friend-request-incoming', from: myFingerprint, username: req.fromUsername }, 'mp');
      send(socket, { t:'friend-request-sent', to, username: req.toUsername });
      return;
    }
    if(msg.t === 'friend-response' && et(conn)==='mp'){
      if(typeof msg.from !== 'string') return;
      const idx = data.friendRequests.findIndex(r=>r.from===msg.from && r.to===myFingerprint);
      if(idx===-1) return;
      const req = data.friendRequests[idx];
      data.friendRequests.splice(idx,1);
      if(msg.accept){
        addFriendship(myFingerprint, msg.from);
        saveData();
        const me = myClient(conn);
        sendTo(msg.from, { t:'friend-added', fingerprint: myFingerprint, username: me.username, pubJwk: me.pubJwk }, 'mp');
        send(socket, { t:'friend-added', fingerprint: msg.from, username: req.fromUsername, pubJwk: (data.knownUsers[msg.from]||{}).pubJwk||null });
      } else {
        saveData();
        sendTo(msg.from, { t:'friend-declined', fingerprint: myFingerprint }, 'mp');
      }
      return;
    }
    if(msg.t === 'block-user' && et(conn)==='mp'){
      if(actionThrottled(myFingerprint, 'block-user', 200)) return;
      const target = msg.target;
      if(typeof target !== 'string' || !target || target===myFingerprint) return;
      if(!data.blocks[myFingerprint]) data.blocks[myFingerprint] = [];
      if(!data.blocks[myFingerprint].includes(target)) data.blocks[myFingerprint].push(target);
      removeFriendship(myFingerprint, target);
      data.friendRequests = data.friendRequests.filter(r=> !((r.from===myFingerprint&&r.to===target)||(r.from===target&&r.to===myFingerprint)));
      saveData();
      send(socket, { t:'blocked-user', fingerprint: target });
      sendTo(target, { t:'friend-removed', fingerprint: myFingerprint }, 'mp');
      return;
    }
    if(msg.t === 'unblock-user' && et(conn)==='mp'){
      if(actionThrottled(myFingerprint, 'unblock-user', 200)) return;
      if(data.blocks[myFingerprint] && typeof msg.target === 'string') data.blocks[myFingerprint] = data.blocks[myFingerprint].filter(f=>f!==msg.target);
      saveData();
      send(socket, { t:'unblocked-user', fingerprint: msg.target });
      return;
    }

    /* ===== GROUPES MP ===== */
    if(msg.t === 'create-group' && et(conn)==='mp'){
      if(actionThrottled(myFingerprint, 'create-group', 800)) return;
      if(Object.keys(data.groups).length >= 5000) return;
      const members = (Array.isArray(msg.members) ? msg.members : [])
        .filter(fp=> typeof fp === 'string' && isFriend(myFingerprint, fp))
        .slice(0, 99);
      if(!members.length) return;
      const id = 'g_' + nodeCrypto.randomBytes(8).toString('hex');
      const group = { id, name: str(msg.name, 40) || 'Groupe', members: [myFingerprint, ...members], createdBy: myFingerprint, ts: Date.now() };
      data.groups[id] = group;
      data.groupMessages[id] = [];
      saveData();
      const payload = groupPayload(group);
      send(socket, { t:'group-created', group: payload });
      for(const m of members) sendTo(m, { t:'group-created', group: payload }, 'mp');
      return;
    }
    if(msg.t === 'add-group-member' && et(conn)==='mp'){
      if(actionThrottled(myFingerprint, 'add-group-member', 300)) return;
      if(typeof msg.groupId !== 'string' || !hasOwn(data.groups, msg.groupId)) return;
      const group = data.groups[msg.groupId];
      if(group.createdBy !== myFingerprint) return; // seul le créateur gère les membres du groupe
      const target = msg.target;
      if(typeof target !== 'string' || !target || group.members.includes(target)) return;
      if(!isFriend(myFingerprint, target)) return; // il faut être ami pour pouvoir dériver la clé pair-à-pair
      if(group.members.length >= 100) return;
      group.members.push(target);
      saveData();
      const payload = groupPayload(group);
      for(const m of group.members){
        if(m === target) sendTo(m, { t:'group-created', group: payload }, 'mp'); // nouveau membre : comme s'il rejoignait
        else sendTo(m, { t:'group-updated', group: payload }, 'mp');             // membres existants : liste rafraîchie (déclenche le partage de la clé au nouveau)
      }
      return;
    }
    if(msg.t === 'remove-group-member' && et(conn)==='mp'){
      if(actionThrottled(myFingerprint, 'remove-group-member', 300)) return;
      if(typeof msg.groupId !== 'string' || !hasOwn(data.groups, msg.groupId)) return;
      const group = data.groups[msg.groupId];
      if(group.createdBy !== myFingerprint) return;
      const target = msg.target;
      if(typeof target !== 'string' || target === myFingerprint || !group.members.includes(target)) return;
      group.members = group.members.filter(m=>m!==target);
      const gvm = groupVoiceMembers.get(msg.groupId);
      if(gvm) gvm.delete(target);
      saveData();
      sendTo(target, { t:'group-removed', groupId: group.id }, 'mp');
      if(group.members.length === 0){
        delete data.groups[msg.groupId];
        delete data.groupMessages[msg.groupId];
        groupVoiceMembers.delete(msg.groupId);
        saveData();
        return;
      }
      const payload = groupPayload(group);
      for(const m of group.members) sendTo(m, { t:'group-updated', group: payload }, 'mp');
      return;
    }
    if(msg.t === 'group-message' && et(conn)==='mp'){
      if(typeof msg.groupId !== 'string' || !hasOwn(data.groups, msg.groupId)) return;
      const group = data.groups[msg.groupId];
      if(!group.members.includes(myFingerprint)) return;
      const tempId = (typeof msg.tempId === 'string') ? msg.tempId.slice(0,64) : undefined;
      if(rateLimited(myFingerprint)){ send(socket, { t:'rate-limited', scope:'group', scopeId: msg.groupId, tempId }); return; }
      if(ciphertextTooLarge(msg.ct) || typeof msg.iv !== 'string'){ send(socket, { t:'error', message:`Message trop long (max ~${config.maxMessageLength} caractères).`, tempId }); return; }
      const id = 'm_'+nodeCrypto.randomBytes(8).toString('hex');
      const entry = { id, from: myFingerprint, iv: msg.iv, ct: msg.ct, ts: Date.now(), deliveredTo: [myFingerprint], readBy: [myFingerprint] };
      data.groupMessages[msg.groupId].push(entry);
      if(data.groupMessages[msg.groupId].length > MAX_HISTORY) data.groupMessages[msg.groupId].shift();
      saveData();
      send(socket, { t:'group-message-ack', groupId: msg.groupId, id, ts: entry.ts, tempId });
      for(const m of group.members){
        if(m !== myFingerprint) sendTo(m, { t:'group-relay', groupId: msg.groupId, id, from: myFingerprint, iv: msg.iv, ct: msg.ct, ts: entry.ts }, 'mp');
      }
      return;
    }
    if(msg.t === 'get-group-history' && et(conn)==='mp'){
      if(typeof msg.groupId !== 'string' || !hasOwn(data.groups, msg.groupId)) return;
      const group = data.groups[msg.groupId];
      if(!group.members.includes(myFingerprint)) return;
      send(socket, { t:'group-history', groupId: msg.groupId, messages: data.groupMessages[msg.groupId]||[] });
      return;
    }
    if(msg.t === 'edit-message' && msg.scope==='group' && et(conn)==='mp'){
      if(typeof msg.scopeId !== 'string' || !hasOwn(data.groups, msg.scopeId)) return;
      const group = data.groups[msg.scopeId];
      if(!group.members.includes(myFingerprint)) return;
      const list = data.groupMessages[msg.scopeId]||[];
      const entry = list.find(e=>e.id===msg.id);
      if(!entry || entry.deleted || entry.from !== myFingerprint) return;
      if(ciphertextTooLarge(msg.ct) || typeof msg.iv !== 'string'){ send(socket, { t:'error', message:`Message trop long (max ~${config.maxMessageLength} caractères).` }); return; }
      entry.iv = msg.iv; entry.ct = msg.ct; entry.editedTs = Date.now();
      saveData();
      for(const m of group.members) sendTo(m, { t:'message-edited', scope:'group', scopeId: msg.scopeId, id: msg.id, iv: msg.iv, ct: msg.ct, editedTs: entry.editedTs }, 'mp');
      return;
    }
    if(msg.t === 'delete-message' && msg.scope==='group' && et(conn)==='mp'){
      if(typeof msg.scopeId !== 'string' || !hasOwn(data.groups, msg.scopeId)) return;
      const group = data.groups[msg.scopeId];
      if(!group.members.includes(myFingerprint)) return;
      const list = data.groupMessages[msg.scopeId]||[];
      const entry = list.find(e=>e.id===msg.id);
      if(!entry) return;
      const allowed = entry.from === myFingerprint || group.createdBy === myFingerprint;
      if(!allowed) return;
      entry.deleted = true; entry.iv = null; entry.ct = null;
      saveData();
      for(const m of group.members) sendTo(m, { t:'message-deleted', scope:'group', scopeId: msg.scopeId, id: msg.id }, 'mp');
      return;
    }
    if(msg.t === 'leave-group' && et(conn)==='mp'){
      if(typeof msg.groupId !== 'string' || !hasOwn(data.groups, msg.groupId)) return;
      const group = data.groups[msg.groupId];
      if(!group.members.includes(myFingerprint)) return;
      group.members = group.members.filter(m=>m!==myFingerprint);
      if(group.members.length === 0){
        delete data.groups[msg.groupId];
        delete data.groupMessages[msg.groupId];
        groupVoiceMembers.delete(msg.groupId);
        saveData();
        send(socket, { t:'group-removed', groupId: msg.groupId });
      } else {
        // si la créatrice/créateur part, le groupe ne doit pas rester bloqué sans personne pour
        // gérer les membres : on transfère la "propriété" à quelqu'un qui reste.
        if(group.createdBy === myFingerprint) group.createdBy = group.members[0];
        saveData();
        send(socket, { t:'group-removed', groupId: msg.groupId });
        const payload = groupPayload(group);
        for(const m of group.members) sendTo(m, { t:'group-updated', group: payload }, 'mp');
      }
      return;
    }
    if((msg.t === 'join-group-voice' || msg.t === 'leave-group-voice') && et(conn)==='mp'){
      if(typeof msg.groupId !== 'string' || !hasOwn(data.groups, msg.groupId)) return;
      const group = data.groups[msg.groupId];
      if(!group.members.includes(myFingerprint)) return;
      if(!groupVoiceMembers.has(msg.groupId)) groupVoiceMembers.set(msg.groupId, new Set());
      const members = groupVoiceMembers.get(msg.groupId);
      if(msg.t === 'join-group-voice') members.add(myFingerprint); else members.delete(myFingerprint);
      for(const fp of group.members) sendTo(fp, { t:'group-voice-roster', groupId:msg.groupId, members:[...members] }, 'mp');
      return;
    }

    /* ===== ACCUSÉS DE RÉCEPTION / LECTURE ===== */
    if(msg.t === 'mark-delivered' || msg.t === 'mark-read'){
      if(typeof msg.scope !== 'string' || typeof msg.scopeId !== 'string' || typeof msg.id !== 'string') return;
      let list = null, members = null;
      if(msg.scope === 'channel' && et(conn)==='channels'){
        list = data.channelMessages[msg.scopeId];
        members = null;
      } else if(msg.scope === 'group' && et(conn)==='mp'){
        if(!hasOwn(data.groups, msg.scopeId)) return;
        const group = data.groups[msg.scopeId];
        if(!group.members.includes(myFingerprint)) return;
        list = data.groupMessages[msg.scopeId];
        members = group.members;
      } else return;
      if(!list) return;
      const entry = list.find(e=>e.id===msg.id);
      if(!entry || entry.deleted) return;
      const field = msg.t === 'mark-read' ? 'readBy' : 'deliveredTo';
      if(!Array.isArray(entry[field])) entry[field] = [];
      if(!entry[field].includes(myFingerprint)) entry[field].push(myFingerprint);
      if(msg.t === 'mark-read'){
        if(!Array.isArray(entry.deliveredTo)) entry.deliveredTo = [];
        if(!entry.deliveredTo.includes(myFingerprint)) entry.deliveredTo.push(myFingerprint);
      }
      const evt = { t: msg.t==='mark-read'?'message-read':'message-delivered', scope: msg.scope, scopeId: msg.scopeId, id: msg.id, fingerprint: myFingerprint };
      if(members){ for(const m of members) if(m!==myFingerprint) sendTo(m, evt, 'mp'); }
      else broadcastExcept(myFingerprint, evt, 'channels');
      return;
    }

    /* ===== RÉACTIONS AUX MESSAGES (style Discord / WhatsApp) ===== */
    if(msg.t === 'toggle-reaction'){
      if(typeof msg.scope !== 'string' || typeof msg.scopeId !== 'string' || typeof msg.id !== 'string') return;
      const emoji = (typeof msg.emoji === 'string') ? msg.emoji.trim().slice(0, 16) : '';
      if(!emoji) return;
      let list = null, members = null;
      if(msg.scope === 'channel' && et(conn)==='channels'){
        if(!canViewChannel(myFingerprint, msg.scopeId)) return;
        list = data.channelMessages[msg.scopeId];
        members = null;
      } else if(msg.scope === 'group' && et(conn)==='mp'){
        if(!hasOwn(data.groups, msg.scopeId)) return;
        const group = data.groups[msg.scopeId];
        if(!group.members.includes(myFingerprint)) return;
        list = data.groupMessages[msg.scopeId];
        members = group.members;
      } else return;
      if(!list) return;
      const entry = list.find(e=>e.id===msg.id);
      if(!entry || entry.deleted) return;
      if(!entry.reactions || typeof entry.reactions !== 'object') entry.reactions = {};
      if(!Array.isArray(entry.reactions[emoji])) entry.reactions[emoji] = [];
      const idx = entry.reactions[emoji].indexOf(myFingerprint);
      if(idx !== -1){
        entry.reactions[emoji].splice(idx, 1);
        if(entry.reactions[emoji].length === 0) delete entry.reactions[emoji];
      } else {
        if(Object.keys(entry.reactions).length < 30 && entry.reactions[emoji].length < 100){
          entry.reactions[emoji].push(myFingerprint);
        }
      }
      saveData();
      const evt = { t:'message-reaction-update', scope: msg.scope, scopeId: msg.scopeId, id: msg.id, reactions: entry.reactions, emoji, by: myFingerprint };
      if(members){
        for(const m of members) sendTo(m, evt, 'mp');
      } else {
        broadcastAll(evt, 'channels');
      }
      return;
    }
  }

  const httpServer = http.createServer((req,res)=>{
    res.writeHead(200, {'Content-Type':'text/plain; charset=utf-8'});
    res.end(`Mesh relay "${config.name}" (${config.type}) — ${clients.size} connecté(s) — port ${config.port}`);
  });

  httpServer.on('upgrade', (req, socket)=>{
    socket.on('error', ()=>{});

    if((req.headers['upgrade']||'').toLowerCase() !== 'websocket'){ socket.destroy(); return; }
    const key = req.headers['sec-websocket-key'];
    if(!key || typeof key !== 'string'){ socket.destroy(); return; }

    const ip = req.socket.remoteAddress || 'unknown';
    const currentIpCount = ipConnCounts.get(ip) || 0;
    if(currentIpCount >= MAX_CONN_PER_IP){ socket.destroy(); return; }
    ipConnCounts.set(ip, currentIpCount + 1);
    let ipReleased = false;
    function releaseIp(){
      if(ipReleased) return;
      ipReleased = true;
      const c = ipConnCounts.get(ip) || 0;
      if(c <= 1) ipConnCounts.delete(ip); else ipConnCounts.set(ip, c-1);
    }

    let acceptKey;
    try{ acceptKey = nodeCrypto.createHash('sha1').update(key + WS_GUID).digest('base64'); }
    catch(e){ socket.destroy(); releaseIp(); return; }
    try{
      socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acceptKey + '\r\n\r\n');
    }catch(e){ releaseIp(); return; }

    let buf = Buffer.alloc(0);
    const conn = {
      fp: null, authenticated: false, pendingAuth: null,
      msgWindowStart: Date.now(), msgWindowCount: 0,
    };

    function teardown(){
      if(conn.pendingAuth && conn.pendingAuth.timeout) clearTimeout(conn.pendingAuth.timeout);
      cleanup(conn.fp, socket);
      releaseIp();
    }

    socket.on('data', (chunk)=>{
      try{ buf = Buffer.concat([buf, chunk]); }catch(e){ try{ socket.destroy(); }catch(e2){} return; }
      if(buf.length > MAX_BUFFER_BYTES){ try{ socket.destroy(); }catch(e){} return; }

      while(true){
        let frame;
        try{ frame = tryParseFrame(buf); }catch(e){ try{ socket.destroy(); }catch(e2){} return; }
        if(!frame) break;
        if(frame.tooLarge){ try{ socket.destroy(); }catch(e){} return; }
        buf = buf.slice(frame.total);

        if(frame.opcode === 8){ try{ socket.end(); }catch(e){} return; }
        if(frame.opcode === 9){ try{ socket.write(encodePong(frame.payload)); }catch(e){} continue; }
        if(frame.opcode === 10){ continue; }
        if(frame.opcode !== 1) continue;

        const now = Date.now();
        if(now - conn.msgWindowStart > 1000){ conn.msgWindowStart = now; conn.msgWindowCount = 0; }
        conn.msgWindowCount++;
        if(conn.msgWindowCount > MAX_MSGS_PER_WINDOW){ try{ socket.destroy(); }catch(e){} return; }

        let msg;
        try{ msg = JSON.parse(frame.payload.toString('utf8')); }catch(e){ continue; }
        if(!msg || typeof msg !== 'object') continue;

        handleMessage(conn, socket, msg).catch(err=>{
          console.error('Erreur de traitement d\'un message (ignorée) :', err && err.message);
        });
      }
    });

    socket.on('close', teardown);
    socket.on('error', teardown);
  });

  httpServer.on('error', (err)=>{
    if(err.code === 'EADDRINUSE'){
      console.error(`\n✗ Le port ${config.port} est déjà utilisé par un autre programme (peut-être une ancienne instance de ce serveur encore ouverte dans un autre terminal).`);
      console.error(`  Ferme l'autre processus, ou change le port dans server-config.json, puis relance.\n`);
    } else if(err.code === 'EACCES'){
      console.error(`\n✗ Permission refusée pour écouter sur le port ${config.port} (les ports < 1024 demandent souvent des droits administrateur).`);
      console.error(`  Choisis un port ≥ 1024 dans server-config.json, puis relance.\n`);
    } else {
      console.error(`\n✗ Impossible de démarrer le serveur :`, err.message, '\n');
    }
    process.exit(1);
  });

  /* ============================================================
     ANNUAIRE CENTRAL (serverListe.js)
     ============================================================ */
  function postJson(urlStr, dataObj, timeoutMs = 4000){
    return new Promise((resolve, reject)=>{
      try{
        const parsed = new URL(urlStr);
        const mod = parsed.protocol === 'https:' ? https : http;
        const payload = Buffer.from(JSON.stringify(dataObj), 'utf8');
        const req = mod.request(parsed, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': payload.length
          },
          timeout: timeoutMs
        }, (res)=>{
          let data = '';
          res.on('data', chunk => { data += chunk; });
          res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(new Error('Timeout')); });
        req.write(payload);
        req.end();
      }catch(err){
        reject(err);
      }
    });
  }

  const serverListCfg = config.serverList || {};
  let serverListHeartbeatTimer = null;

  async function announceToCentralDirectory(){
    if(!serverListCfg.enabled || !serverListCfg.url) return;
    try{
      const targetUrl = serverListCfg.url.replace(/\/+$/, '') + '/api/announce';
      const payload = {
        name: config.name,
        icon: data.icon || config.icon || null,
        type: config.type || 'channels',
        port: config.port,
        host: serverListCfg.publicHost || null,
        description: serverListCfg.description || '',
        userCount: clients.size,
        channels: Array.isArray(data.channels) ? data.channels : []
      };
      await postJson(targetUrl, payload);
    }catch(e){}
  }

  async function leaveCentralDirectory(){
    if(!serverListCfg.enabled || !serverListCfg.url) return;
    try{
      const targetUrl = serverListCfg.url.replace(/\/+$/, '') + '/api/leave';
      const payload = {
        port: config.port,
        host: serverListCfg.publicHost || null
      };
      await postJson(targetUrl, payload, 1500);
    }catch(e){}
  }

  httpServer.listen(config.port, ()=>{
    console.log(`\n=== ${config.name} ${data.icon?`(${data.icon})`:''} ===`);
    console.log(`Type: ${config.type === 'mp' ? 'Relais MP (amis + groupes)' : config.type === 'both' ? 'Les deux à la fois (salons + MP)' : 'Serveur à salons'}`);
    console.log(`En écoute sur le port ${config.port}`);
    console.log(`Les amis se connectent avec : <ton-ip>:${config.port}`);
    console.log(`(pense à rediriger ce port sur ta box si tes amis sont hors de ton réseau local)`);
    if(serverListCfg.enabled && serverListCfg.url){
      console.log(`Annuaire central activé : ${serverListCfg.url}`);
      announceToCentralDirectory();
      serverListHeartbeatTimer = setInterval(announceToCentralDirectory, 30000);
      if(serverListHeartbeatTimer.unref) serverListHeartbeatTimer.unref();
    } else {
      console.log(`Annuaire central : désactivé (serveur privé/local)`);
    }
    console.log('');
  });

  const onShutdown = async ()=>{
    if(serverListHeartbeatTimer) clearInterval(serverListHeartbeatTimer);
    await leaveCentralDirectory();
    process.exit(0);
  };
  process.once('SIGINT', onShutdown);
  process.once('SIGTERM', onShutdown);
}

process.on('uncaughtException', (err)=>{
  console.error('✗ Exception non interceptée (le serveur continue de tourner) :', err && err.stack || err);
});
process.on('unhandledRejection', (err)=>{
  console.error('✗ Rejet de promesse non interceptée (le serveur continue de tourner) :', err && err.stack || err);
});

if(fs.existsSync(CONFIG_PATH)){
  let config;
  try{ config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); }
  catch(e){
    console.error(`\n✗ server-config.json est corrompu ou illisible (${e.message}).`);
    console.error(`  Corrige-le ou supprime-le pour relancer l'assistant de configuration.\n`);
    process.exit(1);
  }
  config.maxMessageLength = Math.min(10000, Math.max(100, parseInt(config.maxMessageLength,10) || 5000));
  runRelayServer(config);
}else{
  runSetupWizard();
}
