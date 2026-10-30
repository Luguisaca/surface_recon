const fs=require('fs'),path=require('path'),assert=require('assert');
const root=process.env.SR_QA_DIR||path.join(process.cwd(),'.qa-browser');
const ui=process.env.SR_UI||'http://127.0.0.1:18044/';
const cdp=process.env.SR_CDP||'http://127.0.0.1:19223';
fs.mkdirSync(root,{recursive:true});
const sleep=n=>new Promise(r=>setTimeout(r,n));
class CDP {
 constructor(u){this.ws=new WebSocket(u);this.id=0;this.pending=new Map();this.ws.onmessage=e=>{const m=JSON.parse(e.data);const p=this.pending.get(m.id);if(p){this.pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result)}}}
 async ready(){await new Promise((r,j)=>{this.ws.onopen=r;this.ws.onerror=j})}
 send(method,params={}){return new Promise((resolve,reject)=>{const id=++this.id;this.pending.set(id,{resolve,reject});this.ws.send(JSON.stringify({id,method,params}));setTimeout(()=>{if(this.pending.has(id)){this.pending.delete(id);reject(Error('timeout '+method))}},10000)})}
 async eval(expr){const r=await this.send('Runtime.evaluate',{expression:expr,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value}
 close(){this.ws.close()}
}
(async()=>{
 const r=await fetch(cdp+'/json/new?about:blank',{method:'PUT'});assert(r.ok);
 const tab=await r.json(),c=new CDP(tab.webSocketDebuggerUrl);await c.ready();
 let out={browser:'Edge',date:new Date().toISOString(),audits:{},issues:[]};
 try{
  await c.send('Page.enable');await c.send('Runtime.enable');await c.send('Accessibility.enable');
  await c.send('Emulation.setDeviceMetricsOverride',{width:390,height:800,deviceScaleFactor:1,mobile:false});
  await c.send('Page.navigate',{url:ui});await sleep(500);
  out.audits.structure=await c.eval("({lang:document.documentElement.lang,viewport:document.querySelector('meta[name=viewport]')?.content,h1:document.querySelectorAll('h1').length,headings:[...document.querySelectorAll('h1,h2,h3')].filter(x=>x.getClientRects().length).map(x=>({level:x.tagName,text:x.textContent.trim()})),liveStatus:{role:document.querySelector('#status').getAttribute('role'),live:document.querySelector('#status').getAttribute('aria-live')},autofocus:document.activeElement.tagName})");
  await c.eval("document.querySelector('details').open=true");
  out.audits.labels=await c.eval("([...document.querySelectorAll('input,button,select')].filter(x=>x.getClientRects().length).map(x=>({id:x.id,tag:x.tagName,name:x.labels?.[0]?.textContent.trim()||x.getAttribute('aria-label')||x.textContent.trim(),width:Math.round(x.getBoundingClientRect().width),height:Math.round(x.getBoundingClientRect().height)})))");
  for(let selector of ['#target','#run','#profile','#noise','summary','#include','#exclude','#authorized']){
   await c.eval("document.querySelector("+JSON.stringify(selector)+").focus()");
   const a=await c.eval("({id:document.activeElement.id,tag:document.activeElement.tagName,outline:getComputedStyle(document.activeElement).outlineStyle,outlineWidth:getComputedStyle(document.activeElement).outlineWidth})");
   out.audits['focus'+selector]=a;
   if(a.outline==='none' && a.outlineWidth==='0px')out.issues.push('no focus ring observed: '+selector);
  }
  await c.eval("document.querySelector('#target').focus()");
  await c.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
  await c.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
  out.audits.keyboard=await c.eval("({active:document.activeElement.id,tag:document.activeElement.tagName})");
  for(let width of [320,390,756,1365]){
   await c.send('Emulation.setDeviceMetricsOverride',{width,height:850,deviceScaleFactor:1,mobile:false});await sleep(70);
   out.audits['layout'+width]=await c.eval("({viewport:innerWidth,doc:document.documentElement.scrollWidth,body:document.body.scrollWidth,form:Math.round(document.querySelector('#target').getBoundingClientRect().width),buttonHeight:Math.round(document.querySelector('#run').getBoundingClientRect().height),minFont:Math.min(...[...document.querySelectorAll('p,button,label,select,input')].filter(x=>x.getClientRects().length).map(x=>parseFloat(getComputedStyle(x).fontSize)))})");
   if(out.audits['layout'+width].doc>width+1)out.issues.push('horizontal overflow: '+width);
  }
  await c.send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  out.audits.reducedMotion=await c.eval("({enabled:matchMedia('(prefers-reduced-motion:reduce)').matches,scrollBehavior:getComputedStyle(document.documentElement).scrollBehavior})");
  out.audits.colors=await c.eval("(['.brand','.muted','.hero p','.helper','#profile-help','#run','.tag','.footer'].map(q=>{let e=document.querySelector(q);let s=getComputedStyle(e);return {selector:q,color:s.color,background:s.backgroundColor,font:s.fontSize}}))");
  const ax=await c.send('Accessibility.getFullAXTree');out.audits.axRoles=ax.nodes.filter(x=>['button','checkbox','combobox','textbox'].includes(x.role?.value)).map(x=>({role:x.role.value,name:x.name?.value||''}));
  if(out.audits.labels.some(x=>!x.name))out.issues.push('visible unnamed control');
  if(out.audits.keyboard.active!=='run')out.issues.push('keyboard tab did not reach run');
  if(out.audits.reducedMotion.scrollBehavior!=='auto')out.issues.push('reduced motion scroll behavior not auto');
  out.result=out.issues.length?'REVIEW':'PASS_BASIC';
 }catch(e){out.result='FAIL';out.error=String(e.stack||e);process.exitCode=1}
 finally{const f=path.join(root,'accessibility.json');fs.writeFileSync(f,JSON.stringify(out,null,2));console.log(JSON.stringify(out,null,2));try{await c.send('Page.close')}catch{}c.close()}
})().catch(e=>{console.error(e);process.exitCode=2});
