"use strict";
const portalOrigin=String(window.WTS_PORTAL_ORIGIN||"https://wts-school-platform.vercel.app").replace(/\/$/,"");
const centralOrigin=window.location.origin.replace(/\/$/,"");
window.WTS_CONFIG=Object.freeze({
  supabaseUrl:"https://wuftzyeajmsxdrbwaawl.supabase.co",
  publishableKey:["sb","publishable","7AKtP6jh9xg8CdrK8F53xA","q4yZskPJ"].join("_"),
  portalOrigin,
  authorizeUri:portalOrigin+"/api/sso/authorize",
  centralOrigin,
  redirectUri:centralOrigin+"/",
});