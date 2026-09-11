"use strict";
const defaultPortalOrigin="https://wts-school-platform.vercel.app";
let requestedPortalOrigin="";
try { requestedPortalOrigin=new URLSearchParams(window.location.search).get("portal_origin") || ""; } catch {}
function trustedPortalOrigin(value) {
  try {
    const parsed=new URL(String(value || defaultPortalOrigin));
    const host=parsed.hostname.toLowerCase();
    const approved=parsed.protocol === "https:" && (host === "portal.waytosuccessschools.com" || host === "wts-school-platform.vercel.app" || /^wts-school-platform-[a-z0-9-]+\.vercel\.app$/.test(host));
    return approved ? parsed.origin : defaultPortalOrigin;
  } catch { return defaultPortalOrigin; }
}
const portalOrigin=trustedPortalOrigin(requestedPortalOrigin || window.WTS_PORTAL_ORIGIN);
const centralOrigin=window.location.origin.replace(/\/$/,"");
window.WTS_CONFIG=Object.freeze({
  supabaseUrl:"https://wuftzyeajmsxdrbwaawl.supabase.co",
  publishableKey:["sb","publishable","7AKtP6jh9xg8CdrK8F53xA","q4yZskPJ"].join("_"),
  portalOrigin,
  authorizeUri:portalOrigin+"/api/sso/authorize",
  centralOrigin,
  redirectUri:centralOrigin+"/",
});
