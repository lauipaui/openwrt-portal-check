// Deterministic public CLI + actual shell + actual DaMod integration. No private keys.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto'),cp=require('node:child_process'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'portal-security-tests-'));
const go=process.env.PORTAL_TEST_GO||'C:/Users/plaui/Documents/Codex/tools/go/bin/go.exe';
const sh=process.env.PORTAL_TEST_SH||'C:/Users/plaui/.cache/codex-runtimes/codex-primary-runtime/dependencies/native/git/usr/bin/sh.exe';
const env={...process.env,GOPATH:process.env.GOPATH||'C:/Users/plaui/Documents/Codex/tools/gopath',GOPROXY:'off',GOSUMDB:'off',GOFLAGS:'-mod=readonly'};
const native=p=>p.replace(/\\/g,'/');
async function run(bin,args,options={}){return new Promise((resolve,reject)=>{const child=cp.spawn(bin,args,{cwd:root,env,...options});let stdout='',stderr='';child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>stderr+=x);child.on('error',reject);child.on('exit',code=>resolve({code,stdout,stderr}));});}
async function ok(bin,args,options){const r=await run(bin,args,options);assert.equal(r.code,0,`${args.join(' ')} failed: ${r.stderr} ${r.stdout}`);return r;}
const key=Buffer.from(Array.from({length:48},(_,i)=>i+1)),iv=Buffer.from(Array.from({length:8},(_,i)=>i+1));
function layer(data,key,decrypt=false){const c=(decrypt?crypto.createDecipheriv:crypto.createCipheriv)('des-ede3-cbc',key,iv);c.setAutoPadding(false);return Buffer.concat([c.update(data),c.final()]);}
function encrypt(s){let b=Buffer.from(s);if(b.length%8)b=Buffer.concat([b,Buffer.alloc(8-b.length%8)]);return layer(layer(b,key.subarray(24)),key.subarray(0,24)).toString('hex').toUpperCase();}
function decrypt(s){return layer(layer(Buffer.from(s,'hex'),key.subarray(0,24),true),key.subarray(24),true).toString().replace(/\0+$/,'');}
(async()=>{
 let srv;
 try{
  const helper=path.join(tmp,process.platform==='win32'?'cipher-helper.exe':'cipher-helper'),damod=path.join(tmp,process.platform==='win32'?'damod.exe':'damod'),moduleFile=path.join(tmp,'fixture.module');
  await ok(go,['build','-o',helper,'.'],{cwd:path.join(root,'cipherhelper')});await ok(go,['build','-o',damod,'.'],{cwd:path.join(root,'tools','damod')});
  await ok(go,['test','-run','TestDeclared16MiBDictionaryWithSmallOutput','-count=1','.'],{cwd:path.join(root,'tools','damod'),env:{...env,PORTAL_TEST_MODULE_OUT:moduleFile}});
  const validModule=fs.readFileSync(moduleFile);let online=false,badDownload=true,rejectAuth=false,keepCount=0,authCount=0,ticketCount=0,pageReads=0;
  const requests=[];
  srv=http.createServer((req,res)=>{const chunks=[];req.on('data',b=>chunks.push(b));req.on('end',()=>{
   const body=Buffer.concat(chunks).toString();requests.push({url:req.url,algo:req.headers['algo-id']});
   if(req.url==='/portal-page'){pageReads++;if(pageReads>1){res.writeHead(204);res.end();return;}const migrated=serverURL.replace('127.0.0.1','localhost');res.end('<!doctype html><html><meta name="x"><br><ticket-url><![CDATA['+migrated+'/ticket.cgi]]></ticket-url><auth-url><![CDATA['+migrated+'/auth.cgi]]></auth-url><script>not xml && never execute</script></html>');return;}
   if(req.url==='/generate_204'){res.writeHead(online?204:200);res.end();return;}
   if(req.url==='/empty200'){res.writeHead(200);res.end();return;}
   if(req.url==='/redirect'){res.writeHead(302,{Location:'/empty200'});res.end();return;}
   if(req.headers['algo-id']==='00000000-0000-0000-0000-000000000000'){res.setHeader('Error-Code','200');res.end(badDownload?validModule.subarray(0,120):validModule);return;}
   try{
    assert.equal(req.headers['algo-id'],'11111111-1111-1111-1111-111111111111');assert.equal(req.headers['cdc-checksum'],crypto.createHash('md5').update(body).digest('hex').toUpperCase());assert.equal(req.headers['cdc-schoolid'],'AUDIT-SCHOOL');
    const decoded=decrypt(body);assert.match(decoded,/^<\?xml/);assert.match(decoded,/<request>/);
    if(req.url.startsWith('/ticket.cgi')){ticketCount++;res.setHeader('Error-Code','0');res.writeHead(200);res.flushHeaders();res.end(encrypt('<response><ticket>public-fixture-ticket</ticket><expire>60</expire></response>'));return;}
    if(req.url==='/auth.cgi'){authCount++;assert.match(decoded,/<userid>fixture<\/userid>/);assert.match(decoded,/<passwd>a&amp;b&lt;c&gt;&#34;&#39;<\/passwd>/);if(rejectAuth){res.setHeader('Error-Code','321');res.end('rejected');return;}res.setHeader('Error-Code','0');res.end(encrypt(`<response><keep-url>${serverURL}/keep.cgi?a=1&amp;b=2</keep-url><keep-retry>120</keep-retry><userid>fixture</userid><user-config/><domain-config/></response>`));return;}
    if(req.url.startsWith('/keep.cgi')){keepCount++;res.setHeader('Error-Code','0');res.writeHead(200);res.flushHeaders();res.end(encrypt('<response><interval>90</interval></response>'));return;}
    throw new Error('unexpected route '+req.url);
   }catch(e){res.writeHead(500);res.end('fixture assertion failed');console.error(e.stack);}
  });});await new Promise(r=>srv.listen(0,'127.0.0.1',r));const serverURL=`http://127.0.0.1:${srv.address().port}`;
  const base=path.join(tmp,'portal');fs.mkdirSync(base,{mode:0o700});fs.copyFileSync(helper,path.join(base,'cipher-helper'+(process.platform==='win32'?'.exe':'')));fs.copyFileSync(damod,path.join(base,'damod'+(process.platform==='win32'?'.exe':'')));
  // Shell expects the stable deployed names; Windows executables run with these names too.
  if(process.platform==='win32'){fs.copyFileSync(helper,path.join(base,'cipher-helper'));fs.copyFileSync(damod,path.join(base,'damod'));}
  fs.copyFileSync(path.join(root,'router','portal_client_openssl.helper.sh'),path.join(base,'portal_client_openssl.sh'));
  if(process.platform!=='win32'){fs.chmodSync(path.join(base,'cipher-helper'),0o700);fs.chmodSync(path.join(base,'damod'),0o700);}
  const cfg=path.join(base,'portal.current.conf');const original={TICKET_URL:serverURL+'/ticket.cgi?clientip=192.0.2.1',AUTH_URL:serverURL+'/auth.cgi',CLIENT_ID:'AUDIT',USER_AGENT:'AUDIT',SCHOOL_ID:'AUDIT-SCHOOL',DOMAIN:'AUDIT-DOMAIN',AREA:'AUDIT-AREA',HOST_NAME:'fixture',OSTAG:'Android',IPV4:'192.0.2.1',IPV6:'',MAC:'02:00:00:00:00:01',GATEWAY:'192.0.2.254',SYSNAME:'Linux',MACHINE:'mips',IFNAME:'wlan0',GSM_NETWORK_TYPE:'NR',SDK:'36',ALGO_ID:'22222222-2222-2222-2222-222222222222',CIPHER_SCHEME:'RAW',RAW_TEMPLATE:'tpl_des_iv.so',RAW_KEY:'11'.repeat(48),RAW_IV:'22'.repeat(16),TRUSTED_PORTAL_HOSTS:'127.0.0.1,localhost'};
  const old=Object.entries(original).map(([k,v])=>`${k}='${v}'`).join('\n')+'\n';fs.writeFileSync(cfg,old);fs.writeFileSync(path.join(base,'portal.user'),'fixture\n');fs.writeFileSync(path.join(base,'portal.password'),'a&b<c>"\'\n');
  const sessions=['portal-session.ticket','portal-session.keep-url','portal-session.interval'];for(const name of sessions)fs.writeFileSync(path.join(base,name),'old-session\n');
  const cached=path.join(base,'damod-update.bin.11111111-1111-1111-1111-111111111111');fs.writeFileSync(cached,'old-corrupt-cache');
  const shellEnv={...env,PATH:path.dirname(sh)+path.delimiter+env.PATH,PORTAL_BASE_DIR:native(base),PORTAL_CIPHER_HELPER:native(path.join(base,'cipher-helper')),PORTAL_PROBE_URL:serverURL+'/generate_204',PORTAL_POST_AUTH_DELAY_SECONDS:'1',PORTAL_POST_AUTH_ATTEMPTS:'1',TMPDIR:native(base)};
  const auto=path.join(root,'router','portal_auto_auth.with-damod.sh');
  let r=await run(sh,[auto,'algo'],{env:shellEnv});assert.notEqual(r.code,0);assert.equal(fs.readFileSync(cfg,'utf8'),old);assert.equal(fs.readFileSync(cached,'utf8'),'old-corrupt-cache');
  badDownload=false;r=await run(sh,[auto,'algo'],{env:shellEnv});assert.notEqual(r.code,0);assert.equal(fs.readFileSync(cfg,'utf8'),old);for(const name of sessions)assert.equal(fs.readFileSync(path.join(base,name),'utf8'),'old-session\n');assert.deepEqual(fs.readFileSync(cached),validModule);
  online=true;rejectAuth=true;r=await run(sh,[auto,'algo'],{env:shellEnv});assert.notEqual(r.code,0);assert.match(r.stderr,/321/);assert.equal(fs.readFileSync(cfg,'utf8'),old);
  rejectAuth=false;await ok(sh,[auto,'algo'],{env:shellEnv});const activated=JSON.parse(fs.readFileSync(cfg,'utf8'));assert.equal(activated.ALGO_ID,'11111111-1111-1111-1111-111111111111');assert.equal(activated.RAW_KEY,key.toString('hex'));assert.equal(activated.SCHOOL_ID,'AUDIT-SCHOOL');assert.equal(fs.readFileSync(path.join(base,'portal-session.ticket'),'utf8'),'public-fixture-ticket\n');
  await ok(sh,[auto,'keep'],{env:shellEnv});assert.equal(keepCount,1);assert.ok(authCount>=3&&ticketCount>=3);
  await ok(helper,['probe',serverURL+'/generate_204','2']);for(const route of ['/empty200','/redirect']){r=await run(helper,['probe',serverURL+route,'2']);assert.notEqual(r.code,0);r=await run(sh,[auto,'check'],{env:{...shellEnv,PORTAL_PROBE_URL:serverURL+route}});assert.notEqual(r.code,0);}
  await ok(sh,[auto,'refresh'],{env:{...shellEnv,PORTAL_PROBE_URL:serverURL+'/portal-page'}});const endpoints=JSON.parse(fs.readFileSync(cfg,'utf8'));assert.match(endpoints.AUTH_URL,/localhost/);assert.ok(endpoints.TICKET_URL.endsWith('?clientip=192.0.2.1'));
  const badcfg=path.join(base,'malicious.conf'),marker=path.join(base,'injection-marker');fs.writeFileSync(badcfg,`AUTH_URL='${serverURL}/auth.cgi';touch '${native(marker)}';#\n`);r=await run(helper,['config-get',badcfg,'AUTH_URL']);assert.notEqual(r.code,0);assert.equal(fs.existsSync(marker),false);
  // Public-build check must fail on unloaded static keys and never emit ciphertext.
  r=await run(helper,['check','07E824B2-9E5C-4D1B-BBB0-5E07C251E4AA']);assert.notEqual(r.code,0);assert.equal(r.stdout,'');assert.doesNotMatch(r.stderr,/panic:/);
  r=await run(helper,['encrypt-raw','tpl_des_ecb.so','0123456789abcdef0123456789abcdef']);assert.notEqual(r.code,0);assert.equal(r.stdout,'');assert.doesNotMatch(r.stderr,/panic:/);
  console.log('PASS actual CLI/shell/DaMod: truncated cache retry; verified replacement; raw auth/keep; candidate rejection + 200 rollback; strict204; injection; no-key/DES16 controlled failure; chunked HTTP; non-XML HTML endpoint candidate activation.');
 }finally{if(srv)await new Promise(r=>srv.close(r));fs.rmSync(tmp,{recursive:true,force:true});}
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
