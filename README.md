# Discord Age Verification Bypasser

A browser-based script to bypass Discord's age verification system by accessing the verification flow directly.

## ⚠️ Disclaimer
This tool is for educational purposes only. Use at your own risk. Bypassing age restrictions may violate Discord's Terms of Service and could result in account termination.

## 🚀 Usage

1. Navigate to Discord in your web browser
2. Open the browser developer tools by pressing **F12** (or Right Click → Inspect)
3. Go to the **Console** tab
4. Paste the entire script code below into the console
5. Press **Enter** to execute

## 📋 Script Code

```javascript
**Execution Instructions:**
1. Open Discord in browser
2. Open DevTools (F12) → Console
3. Paste entire script and press Enter
4. Script automatically redirects to verification page upon success

**Alternative Compact Version (Minified):**
```javascript
eval(async function(){let w=webpackChunkdiscord_app.push([[Symbol()],{},e=>e]);webpackChunkdiscord_app.pop();let m=w.m,c=w.c,f=s=>{for(let i in m)if(m[i].toString().includes(s))return c[i].exports},a=Object.values(f('.set("X-Audit-Log-Reason",')).find(e=>e.patch),tid=crypto.randomUUID(),ts=Date.now(),n=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),hkdf=async(i,s,info,l)=>{let k=await crypto.subtle.importKey('raw',i,{name:'HMAC',hash:'SHA-256'},false,['sign']),prk=await crypto.subtle.sign('HMAC',k,s),T=new Uint8Array(0),okm=new Uint8Array(l),cur=new Uint8Array(0);for(let j=1;j<=Math.ceil(l/32);j++){let hk=await crypto.subtle.importKey('raw',prk,{name:'HMAC',hash:'SHA-256'},false,['sign']),msg=new Uint8Array([...cur,...info,j]);cur=new Uint8Array(await crypto.subtle.sign('HMAC',hk,msg));okm.set(cur,(j-1)*32)}return okm},g=()=>{let u=0,v=0;while(u===0)u=Math.random();while(v===0)v=Math.random();return Math.sqrt(-2*Math.log(u))*Math.cos(2*Math.PI*v)},raws=[];for(let i=0;i<64;i++){let val=127+40*g();raws.push(Math.min(255,Math.max(0,Math.round(val)))};let l=raws.map(r=>1/(1+Math.exp(-(r-127)/20))),rmOut=(arr,p)=>{let d=[...arr];for(let i=0;i<p;i++){let m=d.reduce((a,b)=>a+b,0)/d.length,var_=d.reduce((a,b)=>a+Math.pow(b-m,2),0)/d.length,s=Math.sqrt(var_);d=d.filter(v=>Math.abs(v-m)<=3*s)}return d},out=rmOut(l,2),prim=rmOut(l,1),seed=ts%1e3,x=seed<500?.0005:-.0005,y=seed<500?.0002:-.0002,devs=await navigator.mediaDevices.enumerateDevices(),vid=devs.find(d=>d.kind==='videoinput'),dev={deviceId:vid?.deviceId||'default',groupId:vid?.groupId||'',kind:'videoinput',label:vid?.label||'FaceTime HD Camera'},bt=performance.now(),timeline=[bt,bt+45+90*Math.random(),bt+120+150*Math.random(),bt+190+120*Math.random(),bt+250+180*Math.random()],fp={userAgent:navigator.userAgent,language:navigator.language,platform:navigator.platform,screenWidth:screen.width,screenHeight:screen.height,colorDepth:screen.colorDepth,timezoneOffset:new Date().getTimezoneOffset(),cookiesEnabled:navigator.cookieEnabled,webdriver:navigator.webdriver,hardwareConcurrency:navigator.hardwareConcurrency,deviceMemory:navigator.deviceMemory||4},plain={method:3,predictions:{outputs:out,primaryOutputs:prim,raws:raws,xScaledShiftAmt:x,yScaledShiftAmt:y,mediaDeviceInfo:dev,stateTimeline:timeline},browserFingerprint:fp},ikm=new Uint8Array([...n,...new Uint8Array((new BigUint64Array([BigInt(ts)])).buffer),...new TextEncoder().encode(tid)]),salt=new TextEncoder().encode('age-verify-salt-v2'),ictx=new TextEncoder().encode('age-verify-context'),km=await hkdf(ikm,salt,ictx,32),key=await crypto.subtle.importKey('raw',km,{name:'AES-GCM',length:256},false,['encrypt']),enc=await crypto.subtle.encrypt({name:'AES-GCM',iv:iv,tagLength:128},key,new TextEncoder().encode(JSON.stringify(plain))),ea=new Uint8Array(enc),tag=ea.slice(-16),ct=ea.slice(0,-16),b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))),res=await a.post({url:'/age-verification/verify',body:{encrypted_payload:b64(ct),auth_tag:b64(tag),iv:b64(iv),timestamp:Math.floor(ts/1e3),transaction_id:tid}});if(res.body?.verification_webview_url)window.location.href=res.body.verification_webview_url})();
