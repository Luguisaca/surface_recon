const fs=require('fs'),path=require('path'),assert=require('assert');
const root=process.env.SR_QA_DIR||path.join(process.cwd(),'.qa-browser'),dir=path.join(root,'downloads');
const ui=process.env.SR_UI||'http://127.0.0.1:18044/',fixture=process.env.SR_FIXTURE||'http://127.0.0.1:18043/';
const cdp=process.env.SR_CDP||'http://127.0.0.1:19223',noise=process.env.SR_NOISE||'normal';
fs.mkdirSync(dir,{recursive:true});
const wait=t=>new Promise(r=>setTimeout(r,t));
class CDP{
 constructor(url){this.ws=new WebSocket(url);this.seq=0;this.pending=new Map();this.ws.onmessage=e=>{let m=JSON.parse(e.data);let p=this.pending.get(m.id);if(p){this.pending.delete(m.id);m.error?p.reject(new Error(m.error.message)):p.resolve(m.result)}};}
 async ready(){await new Promise((r,j)=>{this.ws.onopen=r;this.ws.onerror=j});}
 send(method,params={}){return new Promise((resolve,reject)=>{let id=++this.seq;this.pending.set(id,{resolve,reject});this.ws.send(JSON.stringify({id,method,params}));setTimeout(()=>{if(this.pending.has(id)){this.pending.delete(id);reject(new Error('timeout '+method));}},16000)})}
 async eval(expr){let r=await this.send('Runtime.evaluate',{expression:expr,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value}
 close(){this.ws.close()}
}
(async()=>{
 const tab=await (await fetch(cdp+'/json/new?about:blank',{method:'PUT'})).json();
 const c=new CDP(tab.webSocketDebuggerUrl);await c.ready();
 let o={browser:'Edge headless CDP',date:new Date().toISOString(),ui,fixture,steps:{},accessibility:{},downloads:[],screenshots:[]};
 try{
  await c.send('Page.enable');await c.send('Runtime.enable');await c.send('Accessibility.enable');
  await c.send('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:dir,eventsEnabled:true});
  await c.send('Emulation.setDeviceMetricsOverride',{width:1365,height:850,deviceScaleFactor:1,mobile:false});
  await c.send('Page.navigate',{url:o.ui});await wait(800);
  o.steps.loaded=await c.eval("({title:document.title,lang:document.documentElement.lang,profiles:[...document.querySelectorAll('#profile option')].map(x=>({value:x.value,text:x.textContent})),width:innerWidth})");
  assert(o.steps.loaded.profiles.some(x=>x.value==='unlimited'));
  o.steps.validation=await c.eval("(async()=>{document.querySelector('#target').value='';document.querySelector('#run').click();let a={msg:document.querySelector('#status').innerText,focus:document.activeElement.id};document.querySelector('#target').value="+JSON.stringify(fixture)+";document.querySelector('#run').click();return {target:a,auth:{msg:document.querySelector('#status').innerText,focus:document.activeElement.id}}})()");
  assert(o.steps.validation.target.focus==='target');assert(o.steps.validation.auth.focus==='authorized');
  o.accessibility.labels=await c.eval("([...document.querySelectorAll('input,select,button')].map(x=>({id:x.id,tag:x.tagName,label:x.labels?.[0]?.innerText.trim()||x.getAttribute('aria-label')||x.innerText.trim()||'',height:Math.round(x.getBoundingClientRect().height)})))");
  let ax=await c.send('Accessibility.getFullAXTree');o.accessibility.nodes=ax.nodes.length;o.accessibility.buttons=ax.nodes.filter(x=>x.role?.value==='button').map(x=>x.name?.value);
  o.accessibility.live=await c.eval("({role:document.querySelector('#status').getAttribute('role'),live:document.querySelector('#status').getAttribute('aria-live')})");
  for(let width of [390,756,1365]){
   await c.send('Emulation.setDeviceMetricsOverride',{width,height:850,deviceScaleFactor:1,mobile:false});await wait(100);
   o.accessibility['width'+width]=await c.eval("({viewport:innerWidth,scrollWidth:document.documentElement.scrollWidth,mainWidth:document.querySelector('main').getBoundingClientRect().width,runHeight:Math.round(document.querySelector('#run').getBoundingClientRect().height)})");
   let ss=await c.send('Page.captureScreenshot',{format:'png'});let dest=path.join(root,'ui-'+width+'.png');fs.writeFileSync(dest,Buffer.from(ss.data,'base64'));o.screenshots.push(dest);
  }
  await c.send('Emulation.setDeviceMetricsOverride',{width:1365,height:850,deviceScaleFactor:1,mobile:false});
  o.steps.scan=await c.eval("(async()=>{const p=document.querySelector('#profile');p.value='unlimited';document.querySelector('#noise').value="+JSON.stringify(noise)+";p.dispatchEvent(new Event('change',{bubbles:true}));document.querySelector('#authorized').checked=true;document.querySelector('#run').click();for(let i=0;i<150;i++){await new Promise(r=>setTimeout(r,120));if(!document.querySelector('#run').disabled)break}return {profile:p.value,disabled:document.querySelector('#run').disabled,status:document.querySelector('#status').textContent,reportVisible:!document.querySelector('#result').hidden,exportsVisible:!document.querySelector('#exports').hidden,metric:document.querySelector('#metric-status').textContent,reportText:document.querySelector('#human').innerText.slice(0,300)}})()");
  assert(o.steps.scan.profile==='unlimited');assert(o.steps.scan.reportVisible,o.steps.scan.status);assert(o.steps.scan.exportsVisible);
  await c.send('Emulation.setDeviceMetricsOverride',{width:390,height:850,deviceScaleFactor:1,mobile:false});
  o.accessibility.postScanMobile=await c.eval("({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,resultVisible:!document.querySelector('#result').hidden,exportButtons:[...document.querySelectorAll('#exports button')].map(x=>({text:x.innerText,height:Math.round(x.getBoundingClientRect().height)}))})");
  assert(o.accessibility.postScanMobile.scrollWidth<=390,'mobile results cause horizontal document scroll');
  await c.send('Emulation.setDeviceMetricsOverride',{width:1365,height:850,deviceScaleFactor:1,mobile:false});
  for(let id of ['save-html','save-json','save-csv']){await c.eval("document.getElementById("+JSON.stringify(id)+").click()");await wait(900);}
  for(let ext of ['html','json','csv']){
   let files=fs.readdirSync(dir).filter(x=>x.endsWith('.'+ext));assert(files.length===1,ext+' files '+JSON.stringify(files));
   let f=path.join(dir,files[0]),data=fs.readFileSync(f,'utf8');assert(data.length>100,ext+' too small');
   let detail={};
   if(ext==='json'){let j=JSON.parse(data);assert(j.run_id,'missing JSON run_id');detail={run_id:j.run_id,keys:Object.keys(j).slice(0,10)}}
   if(ext==='csv'){assert(data.startsWith('run_id,'),'missing CSV header');detail={rows:data.trim().split(/\r?\n/).length,header:data.split(/\r?\n/)[0].slice(0,180)}}
   if(ext==='html'){assert(data.toLowerCase().includes('<!doctype html>'));detail={hasTable:data.includes('<table'),hasTitle:data.includes('Surface_Recon')}}
   o.downloads.push({ext,file:f,bytes:Buffer.byteLength(data),validated:true,detail});
  }
  let fileUrl='file:///'+o.downloads.find(x=>x.ext==='html').file.replaceAll('\\','/');
  await c.send('Page.navigate',{url:fileUrl});await wait(600);
  o.steps.htmlReopened=await c.eval("({title:document.title,protocol:location.protocol,textSize:document.body?.innerText.length||0,tables:document.querySelectorAll('table').length})");
  assert(o.steps.htmlReopened.protocol==='file:');assert(o.steps.htmlReopened.textSize>100);
  o.steps.outcome='PASS';
 }catch(e){o.steps.outcome='FAIL';o.steps.error=String(e.stack||e);process.exitCode=1}
 finally{fs.writeFileSync(path.join(root,'results.json'),JSON.stringify(o,null,2));console.log(JSON.stringify(o,null,2));try{await c.send('Page.close')}catch{}c.close();}
})().catch(e=>{console.error(e);process.exitCode=2});
