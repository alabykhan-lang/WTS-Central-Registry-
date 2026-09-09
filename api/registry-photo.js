'use strict';

const SUPABASE_URL=process.env.WTS_SUPABASE_URL || 'https://wuftzyeajmsxdrbwaawl.supabase.co';
const SUPABASE_KEY=process.env.WTS_SUPABASE_SERVER_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.WTS_SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
const COOKIE_NAME='wts_registry_session';
const ORIGINS=new Set(['https://wts-central-registry.vercel.app']);

function send(res,status,payload){res.statusCode=status;res.setHeader('Cache-Control','no-store, max-age=0');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(payload));}
function session(req){const raw=String(req.headers.cookie||'').split(';').find((part)=>part.trim().startsWith(`${COOKIE_NAME}=`))?.split('=').slice(1).join('=')||'';let value='';try{value=decodeURIComponent(raw);}catch{return null;}const dot=value.indexOf('.');return dot>0&&dot<value.length-1?{id:value.slice(0,dot),secret:value.slice(dot+1)}:null;}
async function body(req){if(req.body&&typeof req.body==='object')return req.body;let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>600*1024)return null;}try{return raw?JSON.parse(raw):{};}catch{return null;}}
async function rpc(name,payload){try{const response=await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`,{method:'POST',headers:{'Content-Type':'application/json',apikey:SUPABASE_KEY,Authorization:`Bearer ${SUPABASE_KEY}`},body:JSON.stringify(payload)});const result=await response.json().catch(()=>({ok:false,code:'REGISTRY_SERVICE_INVALID_RESPONSE'}));return response.ok?result:{ok:false,code:result.code||'REGISTRY_SERVICE_UNAVAILABLE'};}catch{return {ok:false,code:'REGISTRY_SERVICE_UNAVAILABLE'};}}
function validImage(mime,buffer){if(mime==='image/png')return buffer.length>=8&&buffer.subarray(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]));if(mime==='image/jpeg')return buffer.length>=3&&buffer[0]===0xff&&buffer[1]===0xd8&&buffer[2]===0xff;if(mime==='image/webp')return buffer.length>=12&&buffer.subarray(0,4).toString('ascii')==='RIFF'&&buffer.subarray(8,12).toString('ascii')==='WEBP';return false;}

module.exports=async function registryPhoto(req,res){
  const origin=String(req.headers.origin||'').trim();if(origin&&!ORIGINS.has(origin)&&!String(process.env.WTS_REGISTRY_ALLOWED_ORIGINS||'').split(',').map((x)=>x.trim()).includes(origin))return send(res,403,{ok:false,code:'ORIGIN_NOT_ALLOWED'});
  if(req.method!=='POST')return send(res,405,{ok:false,code:'METHOD_NOT_ALLOWED'});
  const current=session(req);if(!current)return send(res,401,{ok:false,code:'REGISTRY_SESSION_REQUIRED'});
  const input=await body(req);if(!input)return send(res,400,{ok:false,code:'PHOTO_REQUEST_INVALID'});
  const dataUrl=String(input.dataUrl||'');const match=dataUrl.match(/^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/i);if(!match)return send(res,400,{ok:false,code:'PHOTO_IMAGE_INVALID'});
  const buffer=Buffer.from(match[2],'base64');if(!buffer.length||buffer.length>320*1024||!validImage(match[1].toLowerCase(),buffer))return send(res,400,{ok:false,code:'PHOTO_IMAGE_INVALID'});
  const result=await rpc('school_registry_photo_update_session_api',{p_session_id:current.id,p_session_secret:current.secret,p_target_type:String(input.targetType||''),p_target_id:input.targetId||null,p_photo_data:dataUrl,p_request_id:input.requestId||null});
  return send(res,result?.ok?200:(result?.code==='REGISTRY_SCOPE_DENIED'?403:400),result);
};
