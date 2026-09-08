'use strict';

const SUPABASE_URL = process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
// Private Storage operations must never rely on a browser-safe publishable key.
const SUPABASE_KEY = process.env.WTS_SUPABASE_SERVER_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
const COOKIE_NAME = 'wts_registry_session';
const BUCKET = process.env.WTS_SIGNATURE_BUCKET || 'staff-signatures';
const DEFAULT_ORIGIN = 'https://wts-central-registry.vercel.app';
const ALLOWED_ORIGINS = new Set([DEFAULT_ORIGIN]);

function send(res, status, body) {
  res.statusCode = status; res.setHeader('Cache-Control','no-store, max-age=0'); res.setHeader('X-Content-Type-Options','nosniff'); res.setHeader('X-Frame-Options','DENY'); res.setHeader('Referrer-Policy','strict-origin-when-cross-origin'); res.setHeader('Content-Type','application/json; charset=utf-8'); res.end(JSON.stringify(body));
}
function originAllowed(req) { const origin=String(req.headers.origin || '').trim(); return !origin || ALLOWED_ORIGINS.has(origin) || String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS || '').split(',').map((value)=>value.trim()).filter(Boolean).includes(origin); }
function storagePath(path) { return path.split('/').map((segment)=>encodeURIComponent(segment)).join('/'); }
function session(req) {
  const raw = String(req.headers.cookie || '').split(';').find((part) => part.trim().startsWith(`${COOKIE_NAME}=`))?.split('=').slice(1).join('=') || '';
  let value = ''; try { value = decodeURIComponent(raw); } catch { return null; }
  const dot = value.indexOf('.'); return dot > 0 && dot < value.length - 1 ? { id:value.slice(0,dot), secret:value.slice(dot+1) } : null;
}
async function body(req) { if (req.body && typeof req.body === 'object') return req.body; let raw=''; for await (const chunk of req) { raw += chunk; if (raw.length > 3 * 1024 * 1024) return null; } try { return raw ? JSON.parse(raw) : {}; } catch { return null; } }
async function rpc(name,payload) { try { const r=await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`,{method:'POST',headers:{'Content-Type':'application/json',apikey:SUPABASE_KEY,Authorization:`Bearer ${SUPABASE_KEY}`},body:JSON.stringify(payload)}); return r.json().catch(()=>({ok:false,code:'REGISTRY_SERVICE_INVALID_RESPONSE'})); } catch { return {ok:false,code:'REGISTRY_SERVICE_UNAVAILABLE'}; } }
function validImageBuffer(mime, buffer) {
  if (mime === 'image/png') return buffer.length >= 8 && buffer.subarray(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]));
  if (mime === 'image/jpeg') return buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  if (mime === 'image/webp') return buffer.length >= 12 && buffer.subarray(0,4).toString('ascii') === 'RIFF' && buffer.subarray(8,12).toString('ascii') === 'WEBP';
  return false;
}

module.exports = async function registrySignature(req,res) {
  if (!originAllowed(req)) return send(res,403,{ok:false,code:'ORIGIN_NOT_ALLOWED'});
  if (req.method !== 'POST') return send(res,405,{ok:false,code:'METHOD_NOT_ALLOWED'});
  if (!SUPABASE_KEY) return send(res,503,{ok:false,code:'REGISTRY_SERVICE_KEY_MISSING'});
  const current=session(req); if (!current) return send(res,401,{ok:false,code:'REGISTRY_SESSION_REQUIRED'});
  const input=await body(req); if (!input || typeof input !== 'object') return send(res,400,{ok:false,code:'INVALID_REQUEST'});
  const context=await rpc('school_registry_session_context_v2',{p_session_id:current.id,p_session_secret:current.secret});
  if (!context?.ok) return send(res,['REGISTRY_SERVICE_KEY_MISSING','REGISTRY_SERVICE_UNAVAILABLE','REGISTRY_SERVICE_INVALID_RESPONSE'].includes(context?.code)?503:401,context);
  const actor=String(context.actor?.personId || '');
  if (!/^[0-9a-f-]{36}$/i.test(actor)) return send(res,403,{ok:false,code:'REGISTRY_IDENTITY_NOT_ACTIVE'});
  if (input.operation === 'signed-url') {
    const path=String(context.actor?.signaturePath || '');
    if (!path) return send(res,404,{ok:false,code:'SIGNATURE_NOT_FOUND'});
    if (!new RegExp(`^staff-signatures/${actor}\\.(png|jpg|jpeg|webp)$`,'i').test(path)) return send(res,404,{ok:false,code:'SIGNATURE_PATH_INVALID'});
    let signed; try { signed=await fetch(`${SUPABASE_URL}/storage/v1/object/sign/${encodeURIComponent(BUCKET)}/${storagePath(path)}`,{method:'POST',headers:{'Content-Type':'application/json',apikey:SUPABASE_KEY,Authorization:`Bearer ${SUPABASE_KEY}`},body:JSON.stringify({expiresIn:300})}); } catch { return send(res,502,{ok:false,code:'SIGNATURE_SERVICE_UNAVAILABLE'}); }
    const result=await signed.json().catch(()=>null); if (!signed.ok || !result?.signedURL) return send(res,404,{ok:false,code:'SIGNATURE_URL_UNAVAILABLE'});
    return send(res,200,{ok:true,url:result.signedURL,expiresIn:300});
  }
  const dataUrl=String(input.dataUrl || '');
  const match=dataUrl.match(/^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/i);
  if (!match) return send(res,400,{ok:false,code:'SIGNATURE_IMAGE_INVALID'});
  const buffer=Buffer.from(match[2],'base64'); if (!buffer.length || buffer.length > 2 * 1024 * 1024) return send(res,400,{ok:false,code:'SIGNATURE_IMAGE_TOO_LARGE'});
  if (!validImageBuffer(match[1].toLowerCase(),buffer)) return send(res,400,{ok:false,code:'SIGNATURE_IMAGE_INVALID'});
  const extension=match[1].split('/')[1].replace('jpeg','jpg'); const path=`staff-signatures/${actor}.${extension}`;
  let uploaded; try { uploaded=await fetch(`${SUPABASE_URL}/storage/v1/object/${encodeURIComponent(BUCKET)}/${storagePath(path)}`,{method:'POST',headers:{'Content-Type':match[1],apikey:SUPABASE_KEY,Authorization:`Bearer ${SUPABASE_KEY}`,'x-upsert':'true'},body:buffer}); } catch { return send(res,502,{ok:false,code:'SIGNATURE_SERVICE_UNAVAILABLE'}); }
  if (!uploaded.ok) return send(res,502,{ok:false,code:'SIGNATURE_UPLOAD_FAILED'});
  const saved=await rpc('school_registry_write_v2',{p_session_id:current.id,p_session_secret:current.secret,p_action:'profile.signature.update',p_payload:{signaturePath:path,requestId:input.requestId}});
  return send(res,saved?.ok?200:400,saved);
};
