import { NextRequest, NextResponse } from "next/server";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { Check, ScanResult } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 15;

function privateIp(ip:string):boolean {
  if (ip.includes(":")) {
    const x=ip.toLowerCase();
    return x==="::1" || x==="::" || x.startsWith("fc") || x.startsWith("fd") || x.startsWith("fe8") || x.startsWith("fe9") || x.startsWith("fea") || x.startsWith("feb") || x.startsWith("::ffff:127.") || x.startsWith("::ffff:10.") || x.startsWith("::ffff:192.168.");
  }
  const a=ip.split(".").map(Number);
  return a[0]===0 || a[0]===10 || a[0]===127 || a[0]>=224 || (a[0]===169&&a[1]===254) || (a[0]===172&&a[1]>=16&&a[1]<=31) || (a[0]===192&&a[1]===168) || (a[0]===100&&a[1]>=64&&a[1]<=127);
}
async function assertPublic(host:string) {
  const normalized=host.replace(/^\[|\]$/g,"");
  if (["localhost","localhost.localdomain"].includes(normalized.toLowerCase()) || normalized.endsWith(".local")) throw new Error("Local network targets are not allowed.");
  if (isIP(normalized)) { if(privateIp(normalized)) throw new Error("Private or reserved IP addresses cannot be scanned."); return; }
  const records=await lookup(normalized,{all:true,verbatim:true});
  if(!records.length || records.some(r=>privateIp(r.address))) throw new Error("This hostname resolves to a private or reserved network address.");
}
function check(id:string,title:string,ok:boolean,detail:string,weight:number,statusIfBad:"warning"|"fail"|"info"="warning"):Check { return {id,title,status:ok?"pass":statusIfBad,detail,weight}; }
export async function POST(req:NextRequest) {
  try {
    const body=await req.json().catch(()=>({}));
    if(typeof body.url!=="string" || body.url.length>2048) return NextResponse.json({error:"Enter a valid website URL."},{status:400});
    let target:URL;
    try { target=new URL(body.url.includes("://")?body.url:`https://${body.url}`); } catch { return NextResponse.json({error:"Enter a valid URL, such as https://example.com"},{status:400}); }
    if(!["http:","https:"].includes(target.protocol) || target.username || target.password) return NextResponse.json({error:"Only public HTTP and HTTPS URLs are supported."},{status:400});
    if(target.port && !["80","443"].includes(target.port)) return NextResponse.json({error:"Only standard web ports 80 and 443 are supported."},{status:400});
    const started=Date.now(); let current=target; let response:Response|undefined;
    for(let hop=0;hop<=4;hop++) {
      await assertPublic(current.hostname);
      response=await fetch(current.toString(),{method:"GET",redirect:"manual",signal:AbortSignal.timeout(9000),headers:{"User-Agent":"SecureAI-Security-Check/1.0","Accept":"text/html,application/xhtml+xml,*/*;q=0.8","Range":"bytes=0-4095"},cache:"no-store"});
      if([301,302,303,307,308].includes(response.status)) {
        const location=response.headers.get("location"); if(!location) break;
        if(hop===4) throw new Error("The website exceeded the redirect limit.");
        current=new URL(location,current); if(!["http:","https:"].includes(current.protocol)) throw new Error("Redirected to an unsupported protocol."); continue;
      }
      break;
    }
    if(!response) throw new Error("The website did not return a response.");
    const h=response.headers; const https=current.protocol==="https:";
    const csp=!!h.get("content-security-policy");
    const xfo=!!h.get("x-frame-options") || /frame-ancestors/i.test(h.get("content-security-policy")||"");
    const cookies=h.getSetCookie?.()||[];
    const cookieSecure=cookies.length===0 || cookies.every(c=>/;\s*secure/i.test(c));
    const cookieHttpOnly=cookies.length===0 || cookies.every(c=>/;\s*httponly/i.test(c));
    const checks:Check[]=[
      check("reachability","Website responds",response.ok||response.status<500,`HTTP ${response.status} response received from the target.`,0,"fail"),
      check("https","HTTPS encryption",https,https?"The final destination uses HTTPS.":"The final destination uses unencrypted HTTP.",22,"fail"),
      https ? check("hsts","HTTP Strict Transport Security",!!h.get("strict-transport-security"),h.get("strict-transport-security")?"HSTS header is present.":"HSTS header is missing.",12) : {id:"hsts",title:"HTTP Strict Transport Security",status:"info",detail:"HSTS is only evaluated for HTTPS websites.",weight:0},
      check("csp","Content Security Policy",csp,csp?"A Content-Security-Policy header is present.":"No Content-Security-Policy header was observed.",14),
      check("frame","Clickjacking protection",xfo,xfo?"X-Frame-Options or CSP frame-ancestors is present.":"No frame restriction header was observed.",10),
      check("nosniff","MIME sniffing protection",(h.get("x-content-type-options")||"").toLowerCase()==="nosniff",h.get("x-content-type-options")?`X-Content-Type-Options: ${h.get("x-content-type-options")}`:"X-Content-Type-Options header is missing.",8),
      check("referrer","Referrer Policy",!!h.get("referrer-policy"),h.get("referrer-policy")?`Policy: ${h.get("referrer-policy")}`:"Referrer-Policy header is missing.",6),
      check("permissions","Permissions Policy",!!h.get("permissions-policy"),h.get("permissions-policy")?"Permissions-Policy header is present.":"Permissions-Policy header is missing.",5),
      cookies.length ? check("cookies","Cookie attributes",cookieSecure&&cookieHttpOnly,`${cookies.length} Set-Cookie header(s) inspected; Secure: ${cookieSecure?"present":"missing"}, HttpOnly: ${cookieHttpOnly?"present":"missing"}.`,8) : {id:"cookies",title:"Cookie attributes",status:"info",detail:"No Set-Cookie headers were returned for this request; cookie flags could not be assessed.",weight:0},
      check("server","Server banner exposure",!h.get("server")&&!h.get("x-powered-by"),(!h.get("server")&&!h.get("x-powered-by"))?"No Server or X-Powered-By banner was exposed.":`Observed server metadata: ${[h.get("server"),h.get("x-powered-by")].filter(Boolean).join(" / ")}.`,5)
    ];
    const deductions=checks.reduce((sum,c)=>sum+(c.status==="fail"?c.weight:c.status==="warning"?c.weight*.55:0),0);
    const score=Math.max(0,Math.min(100,Math.round(100-deductions)));
    const grade=score>=85?"Good":score>=65?"Moderate":score>=40?"Needs attention":"Poor";
    const result:ScanResult={id:crypto.randomUUID(),url:target.toString(),hostname:target.hostname,scannedAt:new Date().toISOString(),statusCode:response.status,finalUrl:current.toString(),score,grade,checks,durationMs:Date.now()-started,note:"Score reflects the HTTP/TLS checks observed in this scan. It is not a malware or phishing reputation verdict."};
    return NextResponse.json(result,{headers:{"Cache-Control":"no-store"}});
  } catch(e) {
    const message=e instanceof Error?e.message:"The scan could not be completed.";
    const status=/timeout|fetch failed|ENOTFOUND|ECONNREFUSED/i.test(message)?422:400;
    return NextResponse.json({error:message},{status});
  }
}
