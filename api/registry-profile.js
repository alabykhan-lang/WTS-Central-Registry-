'use strict';

const SUPABASE_URL=process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY=process.env.WTS_SUPABASE_SERVER_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.WTS_SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const COOKIE_NAME='wts_registry_session';
const ORIGINS=new Set(['https://wts-central-registry.vercel.app']);

function send(res,status,payload,clear=false){res.statusCode=status;res.setHeader('Cache-Control','no-store, max-age=0');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('Content-Type','application/json; charset=utf-8');if(clear)res.setHeader('Set-Cookie',`${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);res.end(JSON.stringify(payload));}
function session(req){const raw=String(req.headers.cookie||'').split(';').find((part)=>part.trim().startsWith(`${COOKIE_NAME}=`))?.split('=').slice(1).join('=')||'';let value='';try{value=decodeURIComponent(raw);}catch{return null;}const dot=value.indexOf('.');return dot>0&&dot<value.length-1?{id:value.slice(0,dot),secret:value.slice(dot+1)}:null;}
async function body(req){if(req.body&&typeof req.body==='object')return req.body;let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>32*1024)return null;}try{return raw?JSON.parse(raw):{};}catch{return null;}}
async function rpc(name,payload){try{const response=await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`,{method:'POST',headers:{'Content-Type':'application/json',apikey:SUPABASE_KEY,Authorization:`Bearer ${SUPABASE_KEY}`},body:JSON.stringify(payload)});const result=await response.json().catch(()=>({ok:false,code:'REGISTRY_SERVICE_INVALID_RESPONSE'}));return response.ok?result:{ok:false,code:result.code||'REGISTRY_SERVICE_UNAVAILABLE'};}catch{return {ok:false,code:'REGISTRY_SERVICE_UNAVAILABLE'};}}
function statusFor(code){if(code==='REGISTRY_SERVICE_UNAVAILABLE'||code==='REGISTRY_SERVICE_INVALID_RESPONSE')return 503;if(code==='REGISTRY_SESSION_REQUIRED'||code==='REGISTRY_IDENTITY_NOT_ACTIVE')return 401;if(['REGISTRY_SCOPE_DENIED','REGISTRY_CAPABILITY_DENIED','TARGET_CLASS_OUT_OF_SCOPE'].includes(code))return 403;if(code==='PROFILE_CONFLICT')return 409;return 400;}

module.exports=async function registryProfile(req,res){
  const origin=String(req.headers.origin||'').trim();if(origin&&!ORIGINS.has(origin)&&!String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS||'').split(',').map((x)=>x.trim()).includes(origin))return send(res,403,{ok:false,code:'ORIGIN_NOT_ALLOWED'},true);
  if(req.method!=='POST'){res.setHeader('Allow','POST');return send(res,405,{ok:false,code:'METHOD_NOT_ALLOWED'});}
  const current=session(req);if(!current)return send(res,401,{ok:false,code:'REGISTRY_SESSION_REQUIRED'},true);
  const input=await body(req);if(!input||typeof input!=='object')return send(res,400,{ok:false,code:'PROFILE_REQUEST_INVALID'});
  const action=typeof input.action==='string'?input.action.trim():'';const allowed=new Set(['read','department.update','portfolio.create','portfolio.end','portfolio.access_template']);if(!allowed.has(action))return send(res,400,{ok:false,code:'PROFILE_ACTION_INVALID'});
  const result=action==='portfolio.access_template'
    ? await rpc('school_registry_profile_access_template_session_api',{p_session_id:current.id,p_session_secret:current.secret,p_target_type:input.targetType||null,p_target_id:input.targetId||null,p_assignment_id:input.assignmentId||null,p_access_template_code:input.accessTemplateCode||null,p_request_id:input.requestId||null})
    : await rpc('school_registry_profile_session_api',{p_session_id:current.id,p_session_secret:current.secret,p_action:action,p_target_type:input.targetType||null,p_target_id:input.targetId||null,p_department_code:input.departmentCode||null,p_portfolio_name:input.portfolioName||null,p_portfolio_description:input.portfolioDescription||null,p_assignment_id:input.assignmentId||null,p_request_id:input.requestId||null});
  const clear=['REGISTRY_SESSION_REQUIRED','REGISTRY_IDENTITY_NOT_ACTIVE'].includes(result?.code);return send(res,result?.ok?200:statusFor(result?.code),result,clear);
};
