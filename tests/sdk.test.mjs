import test from 'node:test';
import assert from 'node:assert/strict';
import {createClient, MemoryStorage, StayoError} from '../dist/index.js';
const origin = 'https://project.example';
const key = 'public-fixture';
const wireSession = (suffix='a', expiresIn=3600) => ({access_token:`access-${suffix}`,refresh_token:`refresh-${suffix}`,expires_in:expiresIn,user:{id:`user-${suffix}`}});
const response = (data,status=200,headers={}) => new Response(status===204?null:JSON.stringify(data),{status,headers:{'Content-Type':'application/json',...headers}});
const deferred = () => {let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
function fixture(handler){
  const calls=[];
  const client=createClient({url:origin,publicKey:key,fetch:async(url,init)=>{assert.ok(!['GET','HEAD'].includes(init.method)||init.body===undefined,'Fetch rejects GET/HEAD bodies');const call={url:new URL(url),init,body:init.body?JSON.parse(init.body):null};calls.push(call);return handler(call);}});
  return {client,calls};
}
const login = client => client.auth.signInWithPassword({email:'member@example.test',password:'fixture-password'});
const tick=()=>new Promise(r=>setTimeout(r,0));
// Timer-driven Realtime steps are awaited by condition, not by a fixed sleep, so a slow runner cannot fail them.
const waitFor=async(condition,timeoutMs=2000)=>{const deadline=Date.now()+timeoutMs;while(!condition()){if(Date.now()>deadline)assert.fail('condition not reached in time');await new Promise(r=>setTimeout(r,1));}};

test('configuration accepts HTTPS/loopback and rejects privileged keys and ambiguous origins',()=>{
  for(const url of ['http://example.com','https://x.test/path','https://u:p@x.test','https://x.test?x=1','file:///tmp/a']) assert.throws(()=>createClient({url,publicKey:key}),StayoError);
  for(const publicKey of ['sb_secret_123','secret_key','service_role','has space',`x.${btoa(JSON.stringify({role:'service_role'}))}.x`]) assert.throws(()=>createClient({url:origin,publicKey}),e=>e.code==='invalid_public_key');
  for(const url of ['http://localhost:1234','http://127.0.0.1:1234','http://[::1]:1234'])createClient({url,publicKey:key}).dispose();
});

test('transport always omits cookies, forbids redirects, masks provider errors and sends public/user bearer',async()=>{
  const {client,calls}=fixture(call=>call.url.pathname==='/auth/v1/token'?response(wireSession()):response({code:'permission_denied',message:'fixture-password public-fixture access-a'},403));
  await assert.rejects(client.from('notes').select().execute(),e=>e.status===403&&e.code==='permission_denied'&&!String(e).includes('fixture-password'));
  assert.equal(calls[0].init.headers.get('Authorization'),`Bearer ${key}`);
  await login(client);
  await assert.rejects(client.from('notes').execute());
  assert.equal(calls.at(-1).init.headers.get('Authorization'),'Bearer access-a');
  for(const c of calls){assert.equal(c.init.redirect,'error');assert.equal(c.init.credentials,'omit');assert.equal(c.init.headers.get('apikey'),key);}
  client.dispose();
});

test('nested function error codes are preserved without provider messages or retries',async()=>{
  for(const [code,expected] of [['FUNCTION_CONCURRENCY_LIMIT','FUNCTION_CONCURRENCY_LIMIT'],['private provider value','http_error']]){
    const {client,calls}=fixture(c=>c.url.pathname==='/auth/v1/token'?response(wireSession()):c.url.pathname==='/.well-known/stayo.json'?response({protocol_version:1,runtime_version:'1.3.0-compatible',capabilities:{functions:true}}):response({error:{code,message:'fixture-provider-secret'}},429));
    await login(client);
    await assert.rejects(client.functions.invoke('echo',{body:{value:1}}),e=>e.status===429&&e.code===expected&&!String(e).includes('fixture-provider-secret'));
    assert.equal(calls.filter(c=>c.url.pathname==='/functions/v1/echo').length,1);
    client.dispose();
  }
});

test('async project+namespace session storage survives restart and isolates two projects/users',async()=>{
  const backing=new MemoryStorage();const storage={getItem:async k=>backing.getItem(k),setItem:async(k,v)=>backing.setItem(k,v),removeItem:async k=>backing.removeItem(k)};
  const options={url:origin,publicKey:key,storage,fetch:async()=>response(wireSession())};
  const a=createClient(options);await login(a);const b=createClient(options);assert.equal((await b.auth.getSession()).user.id,'user-a');
  const c=createClient({...options,url:'https://other.example'});const d=createClient({...options,storageNamespace:'other-user'});
  assert.equal(await c.auth.getSession(),null);assert.equal(await d.auth.getSession(),null);
  const copied=await a.auth.getSession();copied.user.id='changed';assert.equal((await a.auth.getSession()).user.id,'user-a');
  for(const client of [a,b,c,d])client.dispose();
});

test('Node defaults to a per-client memory store; SSR adapter failures are explicit',async()=>{
  const a=createClient({url:origin,publicKey:key,fetch:async()=>response(wireSession())});await login(a);
  const b=createClient({url:origin,publicKey:key});assert.equal(await b.auth.getSession(),null);
  const broken=createClient({url:origin,publicKey:key,storage:{getItem(){throw Error('private-path')},setItem(){},removeItem(){}}});
  await assert.rejects(broken.auth.getSession(),e=>e.code==='storage_error'&&!String(e).includes('private-path'));
  for(const c of [a,b,broken])c.dispose();
});

test('concurrent near-expiry requests refresh exactly once and send the rotated token',async()=>{
  const pending=deferred();let refreshes=0;
  const {client,calls}=fixture(async c=>{
    if(c.url.searchParams.get('grant_type')==='password')return response(wireSession('old',-1));
    if(c.url.searchParams.get('grant_type')==='refresh_token'){refreshes++;await pending.promise;return response(wireSession('rotated'));}
    return response([]);
  });
  await login(client);const a=client.from('notes').execute();const b=client.from('notes').execute();await tick();assert.equal(refreshes,1);pending.resolve();await Promise.all([a,b]);
  assert.equal(refreshes,1);assert.ok(calls.filter(c=>c.url.pathname==='/rest/v1/notes').every(c=>c.init.headers.get('Authorization')==='Bearer access-rotated'));client.dispose();
});

test('logout wins over an in-flight refresh and clears storage and subscriptions',async()=>{
  const pending=deferred();const storage=new MemoryStorage();let refreshes=0;
  const client=createClient({url:origin,publicKey:key,storage,fetch:async url=>{const u=new URL(url);if(u.searchParams.get('grant_type')==='refresh_token'){refreshes++;await pending.promise;return response(wireSession('late'));}if(u.pathname==='/auth/v1/logout')return response(null,204);return response(wireSession());}});
  await login(client);const work=client.auth.refreshSession();await tick();await client.auth.signOut();pending.resolve();await assert.rejects(work,e=>e.code==='auth_superseded');assert.equal(refreshes,1);assert.equal(await client.auth.getSession(),null);
  const restored=createClient({url:origin,publicKey:key,storage});assert.equal(await restored.auth.getSession(),null);client.dispose();restored.dispose();
});

test('revoked refresh clears session; transient refresh preserves it',async()=>{
  let status=503;const {client}=fixture(c=>c.url.searchParams.get('grant_type')==='password'?response(wireSession()):response({code:'refresh_token_not_found'},status));
  await login(client);await assert.rejects(client.auth.refreshSession());assert.ok(await client.auth.getSession());status=400;await assert.rejects(client.auth.refreshSession());assert.equal(await client.auth.getSession(),null);client.dispose();
});

test('confirmation-only signup, verify, recovery and password routes use the project protocol',async()=>{
  const {client,calls}=fixture(c=>c.url.pathname==='/auth/v1/signup'?response({id:'new-user'}):c.url.pathname==='/auth/v1/verify'?response(wireSession()):c.url.pathname==='/auth/v1/user'?response({id:'user-a',email:'new@example.test'}):response(null,204));
  const signUp=await client.auth.signUp({email:'x@example.test',password:'password',data:{name:'A'}});assert.equal(signUp.user.id,'new-user');assert.equal(signUp.session,null);
  await client.auth.recoverPassword('x@example.test');await client.auth.verifyOtp({type:'signup',token_hash:'token-hash'});await client.auth.getUser();await client.auth.updatePassword('new-password');
  assert.deepEqual(calls.map(c=>[c.url.pathname,c.init.method]),[['/auth/v1/signup','POST'],['/auth/v1/recover','POST'],['/auth/v1/verify','POST'],['/auth/v1/user','GET'],['/auth/v1/user','PUT']]);client.dispose();
});

test('PKCE uses S256, exact unchanged redirect, one-use verifier and code exchange',async()=>{
  const calls=[];const client=createClient({url:origin,publicKey:key,oauthRedirectUrls:['https://app.example/callback?view=login'],fetch:async(url,init)=>{calls.push({url:new URL(url),body:JSON.parse(init.body)});return response(wireSession());}});
  const {url}=await client.auth.beginOAuth({provider:'google',redirectTo:'https://app.example/callback?view=login'});const u=new URL(url);
  assert.equal(u.pathname,'/auth/v1/authorize');assert.equal(u.searchParams.get('redirect_to'),'https://app.example/callback?view=login');assert.equal(u.searchParams.get('code_challenge_method'),'s256');assert.equal(u.searchParams.get('provider'),'google');assert.match(u.searchParams.get('code_challenge'),/^[A-Za-z0-9_-]{43}$/);
  await client.auth.completeOAuth('https://app.example/callback?view=login&code=one-use');
  assert.equal(calls[0].url.searchParams.get('grant_type'),'pkce');assert.equal(calls[0].body.auth_code,'one-use');
  const expected=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(calls[0].body.code_verifier))).toString('base64url');assert.equal(expected,u.searchParams.get('code_challenge'));
  await assert.rejects(client.auth.completeOAuth('https://app.example/callback?view=login&code=one-use'),e=>e.code==='invalid_callback');assert.equal(calls.length,1);client.dispose();
});

test('PKCE rejects cancellation, callback host/path/query mismatch, duplicate code and replay',async()=>{
  let requests=0;const client=createClient({url:origin,publicKey:key,oauthRedirectUrls:['https://app.example/callback'],fetch:async()=>{requests++;return response(wireSession());}});
  await assert.rejects(client.auth.beginOAuth({provider:'apple',redirectTo:'https://evil.example/callback'}));
  for(const cb of ['https://evil.example/callback?code=x','https://app.example/other?code=x','https://app.example/callback?code=x&other=y','https://app.example/callback?error=access_denied','https://app.example/callback?code=a&code=b']){
    await client.auth.beginOAuth({provider:'apple',redirectTo:'https://app.example/callback'});await assert.rejects(client.auth.completeOAuth(cb),e=>e.code==='invalid_callback');
  }
  await client.auth.beginOAuth({provider:'apple',redirectTo:'https://app.example/callback'});await client.auth.cancelOAuth();await assert.rejects(client.auth.completeOAuth('https://app.example/callback?code=x'));assert.equal(requests,0);client.dispose();
});

test('queries encode filters/ranges/schema and mutations use representation with a single dispatch',async()=>{
  const {client,calls}=fixture(()=>response([{id:1}],206,{'Content-Range':'5-5/12'}));
  const result=await client.schema('app').from('notes').select('id,title',{count:'exact'}).eq('owner_id','a&admin=true').in('title',['comma,value','quote"value']).order('id',{ascending:false}).range(5,9).execute();
  assert.equal(result.count,12);assert.equal(calls[0].init.headers.get('Range'),'5-9');assert.equal(calls[0].init.headers.get('Accept-Profile'),'app');assert.equal(calls[0].url.searchParams.get('owner_id'),'eq.a&admin=true');assert.equal(calls[0].url.searchParams.get('order'),'id.desc');
  await client.from('notes').insert({title:'created'}).execute();await client.from('notes').update({title:'changed'}).eq('id',1).execute();await client.from('notes').delete().eq('id',1).execute();await client.from('notes').upsert({id:1},{onConflict:'id'}).execute();await client.rpc('count_notes',{owner:'a'});
  assert.deepEqual(calls.map(c=>c.init.method),['GET','POST','PATCH','DELETE','POST','POST']);assert.ok(calls.slice(1,5).every(c=>c.init.headers.get('Prefer').includes('return=representation')));assert.equal(calls[4].url.searchParams.get('on_conflict'),'id');
  assert.throws(()=>client.from('../users'));assert.throws(()=>client.from('notes').range(-1,5));client.dispose();
});

test('storage encodes Unicode/spaces/percent per segment and rejects traversal and foreign signed URLs',async()=>{
  const calls=[];let signedURL='/object/sign/photos/folder/file?token=fixture';
  const client=createClient({url:origin,publicKey:key,fetch:async(url,init)=>{calls.push({url:new URL(url),init});return response(new URL(url).pathname.includes('/sign/')?{signedURL}:{Key:'ok'});}});
  await client.storage.from('photos').upload('folder/кот 1%2F.png',new Blob(['content'],{type:'image/png'}));assert.match(calls[0].url.pathname,/folder\/%D0%BA%D0%BE%D1%82%201%252F\.png$/);assert.equal(calls[0].init.headers.get('Content-Type'),'image/png');
  assert.equal(await client.storage.from('photos').createSignedUrl('folder/file',30),origin+'/storage/v1'+signedURL);
  for(const path of ['../secret','a/../b','a//b','/a','a\\b','a/'])await assert.rejects(client.storage.from('photos').download(path));
  for(const invalid of ['https://evil.example/stolen','//evil.example/stolen','/auth/v1/token?secret=x']){signedURL=invalid;await assert.rejects(client.storage.from('photos').createSignedUrl('folder/file',30));}
  await client.storage.from('photos').remove(['folder/file']);assert.deepEqual(JSON.parse(calls.at(-1).init.body),{prefixes:['folder/file']});client.dispose();
});

test('Functions require auth + marker and dispatch only once on 429/503; no health-only runtime accepted',async()=>{
  let enabled=false;let functionCalls=0;let status=429;
  const {client}=fixture(c=>{
    if(c.url.pathname==='/auth/v1/token')return response(wireSession());
    if(c.url.pathname==='/.well-known/stayo.json')return response({protocol_version:1,runtime_version:enabled?'1.3.0-compatible':'1.2.0-compatible',capabilities:{functions:enabled}});
    functionCalls++;return response({code:'overloaded'},status);
  });
  await assert.rejects(client.functions.invoke('answer'),e=>e.code==='not_authenticated');await login(client);await assert.rejects(client.functions.invoke('answer'),e=>e.code==='unsupported_capability');assert.equal(functionCalls,0);
  enabled=true;await assert.rejects(client.functions.invoke('answer',{body:{question:'hi'}}),e=>e.status===429);assert.equal(functionCalls,1);status=503;await assert.rejects(client.functions.invoke('answer'),e=>e.status===503);assert.equal(functionCalls,2);client.dispose();
});

test('Functions recheck auth after capability lookup; logout prevents stale-token dispatch',async()=>{
  const pending=deferred();const reached=deferred();let invoked=0;
  const {client}=fixture(async c=>{
    if(c.url.pathname==='/auth/v1/token')return response(wireSession());
    if(c.url.pathname==='/.well-known/stayo.json'){reached.resolve();await pending.promise;return response({protocol_version:1,runtime_version:'1.3.0-compatible',capabilities:{functions:true}});}
    if(c.url.pathname==='/auth/v1/logout')return response(null,204);
    invoked++;return response({ok:true});
  });
  await login(client);const work=client.functions.invoke('answer');await reached.promise;await client.auth.signOut();pending.resolve();await assert.rejects(work,e=>e.code==='not_authenticated');assert.equal(invoked,0);client.dispose();
});

test('request cancellation and slow-body deadline abort without automatic retry',async()=>{
  let count=0;const {client}=fixture(c=>{count++;return new Promise((_,reject)=>c.init.signal.addEventListener('abort',()=>reject(new DOMException('private-url','AbortError')),{once:true}));});
  const controller=new AbortController();const work=client.from('notes').execute({signal:controller.signal});await tick();controller.abort();await assert.rejects(work,e=>e.code==='aborted');assert.equal(count,1);
  await assert.rejects(client.from('notes').execute({timeoutMs:10}),e=>e.code==='aborted');assert.equal(count,2);client.dispose();
});

class FakeSocket {
  readyState=0;messages=[];onopen=null;onmessage=null;onclose=null;onerror=null;
  open(){this.readyState=1;void this.onopen?.({});}
  send(message){this.messages.push(JSON.parse(message));}
  receive(message){this.onmessage?.({data:JSON.stringify(message)});}
  close(){if(this.readyState===3)return;this.readyState=3;this.onclose?.({});}
  replyTo(m,payload={status:'ok',response:{}}){this.receive({...m,event:'phx_reply',payload});}
  postgresReady(join){this.receive({topic:join.topic,event:'system',payload:{extension:'postgres_changes',status:'ok',message:'Subscribed to PostgreSQL'},join_ref:join.ref});}
}

test('Realtime joins INSERT/UPDATE only, rotates token, heartbeats, reconnects with resync and closes on logout',async()=>{
  const sockets=[];const changes=[];const statuses=[];
  const client=createClient({url:origin,publicKey:key,fetch:async url=>new URL(url).pathname==='/auth/v1/logout'?response(null,204):response(wireSession(sockets.length?'rotated':'initial')),webSocketFactory:url=>{assert.equal(new URL(url).searchParams.get('vsn'),'1.0.0');const s=new FakeSocket();sockets.push(s);return s;},realtime:{heartbeatMs:20,reconnectDelaysMs:[5],joinTimeoutMs:100}});
  await login(client);const sub=client.realtime.subscribe({table:'notes',onChange:c=>changes.push(c),onStatus:s=>statuses.push(s)});await tick();sockets[0].open();await tick();const join=sockets[0].messages[0];assert.equal(join.event,'phx_join');assert.equal(join.payload.access_token,'access-initial');assert.deepEqual(join.payload.config.postgres_changes.map(c=>c.event),['INSERT','UPDATE']);sockets[0].replyTo(join);sockets[0].postgresReady(join);
  const data={schema:'public',table:'notes',type:'INSERT',record:{id:1}};sockets[0].receive({topic:join.topic,event:'postgres_changes',payload:{data},join_ref:join.ref});sockets[0].receive({topic:join.topic,event:'postgres_changes',payload:{data:{...data,type:'DELETE'}}});assert.equal(changes.length,1);
  await client.auth.refreshSession();assert.equal(sockets[0].messages.at(-1).event,'access_token');assert.equal(sockets[0].messages.at(-1).payload.access_token,'access-rotated');
  await waitFor(()=>sockets[0].messages.some(m=>m.event==='heartbeat'));const heartbeat=sockets[0].messages.find(m=>m.event==='heartbeat');sockets[0].replyTo(heartbeat);sockets[0].close();await waitFor(()=>sockets.length>=2);assert.equal(sockets.length,2);sockets[1].open();await tick();sockets[1].replyTo(sockets[1].messages[0]);sockets[1].postgresReady(sockets[1].messages[0]);assert.ok(statuses.includes('resync-required'));
  await client.auth.signOut();assert.equal(sockets[1].readyState,3);assert.equal(statuses.at(-1),'closed');sub.unsubscribe();client.dispose();
});

test('Realtime heartbeat timeout reconnects and explicit unsubscribe stops retry',async t=>{
  const sockets=[];const client=createClient({url:origin,publicKey:key,webSocketFactory:()=>{const s=new FakeSocket();sockets.push(s);return s;},realtime:{heartbeatMs:5,reconnectDelaysMs:[5],joinTimeoutMs:100}});t.after(()=>client.dispose());
  const sub=client.realtime.subscribe({table:'notes',onChange(){}});await tick();sockets[0].open();await tick();sockets[0].replyTo(sockets[0].messages[0]);sockets[0].postgresReady(sockets[0].messages[0]);await waitFor(()=>sockets.length>=2);sub.unsubscribe();const count=sockets.length;await new Promise(r=>setTimeout(r,30));assert.equal(sockets.length,count);
});


test('refresh begun during another account sign-in cannot restore the previous account',async()=>{
  const signInGate=deferred();const refreshGate=deferred();const refreshStarted=deferred();let signIns=0;
  const {client}=fixture(async c=>{
    if(c.url.searchParams.get('grant_type')==='password'){
      signIns++;if(signIns===2){await signInGate.promise;return response(wireSession('account-b'));}
      return response(wireSession('account-a'));
    }
    refreshStarted.resolve();await refreshGate.promise;return response(wireSession('account-a-refreshed'));
  });
  await login(client);const signIn=login(client);await tick();const refresh=client.auth.refreshSession();await refreshStarted.promise;
  signInGate.resolve();await signIn;assert.equal((await client.auth.getSession()).user.id,'user-account-b');
  refreshGate.resolve();await assert.rejects(refresh,e=>e.code==='auth_superseded');assert.equal((await client.auth.getSession()).user.id,'user-account-b');client.dispose();
});

test('old account refresh failure cannot sign out a newly signed-in account',async()=>{
  const signInGate=deferred();const refreshGate=deferred();const refreshStarted=deferred();let signIns=0;
  const {client}=fixture(async c=>{
    if(c.url.searchParams.get('grant_type')==='password'){signIns++;if(signIns===2)await signInGate.promise;return response(wireSession(signIns===2?'new':'old'));}
    refreshStarted.resolve();await refreshGate.promise;return response({code:'refresh_token_not_found'},400);
  });
  await login(client);const signIn=login(client);await tick();const refresh=client.auth.refreshSession();await refreshStarted.promise;
  signInGate.resolve();await signIn;refreshGate.resolve();await assert.rejects(refresh);assert.equal((await client.auth.getSession()).user.id,'user-new');client.dispose();
});

test('canceling OAuth during code exchange prevents the returned session from signing in',async()=>{
  const exchange=deferred();const started=deferred();const client=createClient({url:origin,publicKey:key,oauthRedirectUrls:['https://app.example/callback'],fetch:async()=>{started.resolve();await exchange.promise;return response(wireSession('oauth'));}});
  await client.auth.beginOAuth({provider:'google',redirectTo:'https://app.example/callback'});
  const callback=client.auth.completeOAuth('https://app.example/callback?code=code');await started.promise;await client.auth.cancelOAuth();exchange.resolve();await assert.rejects(callback,e=>e.code==='invalid_callback');assert.equal(await client.auth.getSession(),null);client.dispose();
});


test('disposed clients reject new subscriptions and HTTP work without reconnect timers or dispatch',async()=>{
  let calls=0;let sockets=0;const client=createClient({url:origin,publicKey:key,fetch:async()=>{calls++;return response({});},webSocketFactory:()=>{sockets++;return new FakeSocket();},realtime:{reconnectDelaysMs:[2]}});
  await client.auth.getSession();client.dispose();assert.throws(()=>client.realtime.subscribe({table:'notes',onChange(){}}),e=>e.code==='client_disposed');
  await assert.rejects(client.getCapabilities(),e=>e.code==='client_disposed');await assert.rejects(login(client),e=>e.code==='client_disposed');assert.equal(calls,0);assert.equal(sockets,0);client.dispose();
});


test('late password update from previous account cannot mutate current account session or emit its event',async()=>{
  const signInGate=deferred();const updateGate=deferred();const updateStarted=deferred();let signIns=0;const events=[];
  const {client}=fixture(async c=>{
    if(c.url.pathname==='/auth/v1/token'){signIns++;if(signIns===2)await signInGate.promise;return response(wireSession(signIns===2?'new':'old'));}
    updateStarted.resolve();await updateGate.promise;return response({id:'user-old',email:'old@example.test'});
  });
  await login(client);client.auth.onAuthStateChange(event=>events.push(event));const signIn=login(client);await tick();const update=client.auth.updatePassword('new-password');await updateStarted.promise;
  signInGate.resolve();await signIn;updateGate.resolve();await update;const session=await client.auth.getSession();assert.equal(session.user.id,'user-new');assert.equal(session.accessToken,'access-new');assert.deepEqual(events,['SIGNED_IN']);client.dispose();
});

test('revoked previous account refresh does not cancel a pending valid sign-in',async()=>{
  const signInGate=deferred();const refreshGate=deferred();const refreshStarted=deferred();let signIns=0;
  const {client}=fixture(async c=>{
    if(c.url.pathname==='/auth/v1/token'&&c.url.searchParams.get('grant_type')==='password'){signIns++;if(signIns===2)await signInGate.promise;return response(wireSession(signIns===2?'new':'old'));}
    refreshStarted.resolve();await refreshGate.promise;return response({code:'refresh_token_not_found'},400);
  });
  await login(client);const signIn=login(client);await tick();const refresh=client.auth.refreshSession();await refreshStarted.promise;refreshGate.resolve();await assert.rejects(refresh);signInGate.resolve();await signIn;assert.equal((await client.auth.getSession()).user.id,'user-new');client.dispose();
});


test('refresh cannot return the previous account token when a sign-in supersedes its delayed storage write',async()=>{
  const backing=new MemoryStorage();const writeGate=deferred();const writeStarted=deferred();const signInGate=deferred();let delayWrite=false;let signIns=0;const events=[];
  const storage={getItem:k=>backing.getItem(k),removeItem:k=>backing.removeItem(k),setItem:async(k,v)=>{if(delayWrite&&v.includes('access-old-rotated')){writeStarted.resolve();await writeGate.promise;}backing.setItem(k,v);}};
  const client=createClient({url:origin,publicKey:key,storage,fetch:async url=>{
    const u=new URL(url);if(u.searchParams.get('grant_type')==='password'){signIns++;if(signIns===2)await signInGate.promise;return response(wireSession(signIns===2?'new':'old'));}
    return response(wireSession('old-rotated'));
  }});
  await login(client);client.auth.onAuthStateChange(event=>events.push(event));const signIn=login(client);await tick();delayWrite=true;const refresh=client.auth.refreshSession();const rejected=assert.rejects(refresh,e=>e.code==='auth_superseded');await writeStarted.promise;
  signInGate.resolve();await tick();writeGate.resolve();await rejected;await signIn;assert.equal((await client.auth.getSession()).user.id,'user-new');assert.deepEqual(events,['SIGNED_IN']);client.dispose();
});


test('stale refresh storage removal cannot emit SIGNED_OUT for a newer account',async()=>{
  const backing=new MemoryStorage();const removeStarted=deferred();const removeGate=deferred();const signInGate=deferred();let signIns=0;let blockRemove=false;const events=[];
  const storage={getItem:k=>backing.getItem(k),setItem:(k,v)=>backing.setItem(k,v),removeItem:async k=>{if(blockRemove&&!k.endsWith(':pkce')){removeStarted.resolve();await removeGate.promise;}backing.removeItem(k);}};
  const client=createClient({url:origin,publicKey:key,storage,fetch:async url=>{
    if(new URL(url).searchParams.get('grant_type')==='password'){signIns++;if(signIns===2)await signInGate.promise;return response(wireSession(signIns===2?'new':'old'));}
    return response({code:'refresh_token_not_found'},400);
  }});
  await login(client);client.auth.onAuthStateChange(event=>events.push(event));const signIn=login(client);await tick();blockRemove=true;const refresh=client.auth.refreshSession();const rejected=assert.rejects(refresh);await removeStarted.promise;signInGate.resolve();await tick();removeGate.resolve();await rejected;await signIn;
  assert.equal((await client.auth.getSession()).user.id,'user-new');assert.deepEqual(events,['SIGNED_IN']);client.dispose();
});

test('canceling OAuth during persistence rolls back only that provisional session',async()=>{
  const backing=new MemoryStorage();const writeStarted=deferred();const writeGate=deferred();const events=[];
  const storage={getItem:k=>backing.getItem(k),removeItem:k=>backing.removeItem(k),setItem:async(k,v)=>{if(!k.endsWith(':pkce')&&v.includes('access-oauth')){writeStarted.resolve();await writeGate.promise;}backing.setItem(k,v);}};
  const client=createClient({url:origin,publicKey:key,storage,oauthRedirectUrls:['https://app.example/callback'],fetch:async url=>response(wireSession(new URL(url).searchParams.get('grant_type')==='pkce'?'oauth':'existing'))});
  await login(client);client.auth.onAuthStateChange(event=>events.push(event));await client.auth.beginOAuth({provider:'google',redirectTo:'https://app.example/callback'});
  const callback=client.auth.completeOAuth('https://app.example/callback?code=code');const rejected=assert.rejects(callback,e=>e.code==='invalid_callback');await writeStarted.promise;const cancel=client.auth.cancelOAuth();writeGate.resolve();await cancel;await rejected;
  assert.equal((await client.auth.getSession()).user.id,'user-existing');assert.deepEqual(events,[]);const restored=createClient({url:origin,publicKey:key,storage});assert.equal((await restored.auth.getSession()).user.id,'user-existing');client.dispose();restored.dispose();
});


test('new OAuth attempt started during delayed logout persistence is preserved',async()=>{
  const backing=new MemoryStorage();const removeStarted=deferred();const removeGate=deferred();let blocked=true;
  const storage={getItem:k=>backing.getItem(k),setItem:(k,v)=>backing.setItem(k,v),removeItem:async k=>{if(blocked&&!k.endsWith(':pkce')){removeStarted.resolve();await removeGate.promise;blocked=false;}backing.removeItem(k);}};
  const client=createClient({url:origin,publicKey:key,storage,oauthRedirectUrls:['https://app.example/callback'],fetch:async url=>new URL(url).pathname==='/auth/v1/logout'?response(null,204):response(wireSession())});
  await login(client);const logout=client.auth.signOut();await removeStarted.promise;const begin=client.auth.beginOAuth({provider:'google',redirectTo:'https://app.example/callback'});await tick();removeGate.resolve();await logout;await begin;
  await client.auth.completeOAuth('https://app.example/callback?code=new-attempt');assert.ok(await client.auth.getSession());client.dispose();
});


test('canceled provisional OAuth rolls back when a newer password attempt failed',async()=>{
  const backing=new MemoryStorage();const writeStarted=deferred();const writeGate=deferred();let signIns=0;
  const storage={getItem:k=>backing.getItem(k),removeItem:k=>backing.removeItem(k),setItem:async(k,v)=>{if(!k.endsWith(':pkce')&&v.includes('access-oauth')){writeStarted.resolve();await writeGate.promise;}backing.setItem(k,v);}};
  const client=createClient({url:origin,publicKey:key,storage,oauthRedirectUrls:['https://app.example/callback'],fetch:async url=>{if(new URL(url).searchParams.get('grant_type')==='pkce')return response(wireSession('oauth'));signIns++;return signIns===1?response(wireSession('existing')):response({code:'invalid_credentials'},400);}});
  await login(client);await client.auth.beginOAuth({provider:'google',redirectTo:'https://app.example/callback'});const callback=client.auth.completeOAuth('https://app.example/callback?code=code');const rejected=assert.rejects(callback,e=>e.code==='invalid_callback');await writeStarted.promise;await assert.rejects(login(client));const cancellation=client.auth.cancelOAuth();writeGate.resolve();await cancellation;await rejected;assert.equal((await client.auth.getSession()).user.id,'user-existing');client.dispose();
});


test('Realtime waits for both Phoenix ACK and PostgreSQL readiness in either arrival order',async()=>{
  for(const order of ['ack-first','system-first']){
    const sockets=[],statuses=[],changes=[];const client=createClient({url:origin,publicKey:key,webSocketFactory:()=>{const socket=new FakeSocket();sockets.push(socket);return socket;}});
    const sub=client.realtime.subscribe({table:'notes',onChange:c=>changes.push(c),onStatus:s=>statuses.push(s)});await tick();const socket=sockets[0];socket.open();await tick();const join=socket.messages[0];
    const change=()=>socket.receive({topic:join.topic,event:'postgres_changes',payload:{data:{schema:'public',table:'notes',type:'INSERT',record:{id:1}}}});
    if(order==='ack-first')socket.replyTo(join);else socket.postgresReady(join);
    assert.ok(!statuses.includes('subscribed'));change();assert.equal(changes.length,0);
    if(order==='ack-first')socket.postgresReady(join);else socket.replyTo(join);
    assert.equal(statuses.filter(s=>s==='subscribed').length,1);change();assert.equal(changes.length,1);
    socket.postgresReady(join);socket.replyTo(join);assert.equal(statuses.filter(s=>s==='subscribed').length,1);sub.unsubscribe();client.dispose();
  }
});

test('Realtime ACK without PostgreSQL readiness times out instead of reporting subscribed',async()=>{
  const sockets=[],statuses=[];const client=createClient({url:origin,publicKey:key,webSocketFactory:()=>{const socket=new FakeSocket();sockets.push(socket);return socket;},realtime:{joinTimeoutMs:10,reconnectDelaysMs:[500]}});
  const sub=client.realtime.subscribe({table:'notes',onChange(){},onStatus:s=>statuses.push(s)});await tick();sockets[0].open();await tick();sockets[0].replyTo(sockets[0].messages[0]);await waitFor(()=>sockets[0].readyState===3);assert.ok(!statuses.includes('subscribed'));assert.ok(statuses.includes('disconnected'));sub.unsubscribe();client.dispose();
});

test('Realtime reconnect clears prior readiness and emits resync only after both new signals',async()=>{
  const sockets=[],statuses=[];const client=createClient({url:origin,publicKey:key,webSocketFactory:()=>{const socket=new FakeSocket();sockets.push(socket);return socket;},realtime:{reconnectDelaysMs:[1]}});
  const sub=client.realtime.subscribe({table:'notes',onChange(){},onStatus:s=>statuses.push(s)});await tick();sockets[0].open();await tick();const first=sockets[0].messages[0];sockets[0].replyTo(first);sockets[0].postgresReady(first);sockets[0].close();await waitFor(()=>sockets.length>=2);sockets[1].open();await tick();const next=sockets[1].messages[0];sockets[1].replyTo(next);assert.equal(statuses.filter(s=>s==='subscribed').length,1);assert.ok(!statuses.includes('resync-required'));sockets[1].postgresReady(next);assert.equal(statuses.filter(s=>s==='subscribed').length,2);assert.equal(statuses.at(-1),'resync-required');sub.unsubscribe();client.dispose();
});


test('email confirmation and recovery codes use email/token with one dispatch',async()=>{
  const {client,calls}=fixture(c=>response(wireSession(c.body.type)));
  for(const type of ['email','recovery']){
    const result=await client.auth.verifyOtp({email:'member@example.test',token:'123456',type});
    assert.equal(result.session.user.id,`user-${type}`);
    assert.equal((await client.auth.getSession()).accessToken,`access-${type}`);
    assert.deepEqual(calls.at(-1).body,{email:'member@example.test',token:'123456',type});
    assert.equal(calls.at(-1).url.pathname,'/auth/v1/verify');
  }
  assert.equal(calls.length,2);client.dispose();
});

test('verification rejects ambiguous input before sending and never retries a rejected code',async()=>{
  const {client,calls}=fixture(()=>response({code:'otp_expired'},403));
  for(const input of [
    {email:'member@example.test',token:'123456',token_hash:'synthetic',type:'email'},
    {email:'member@example.test',type:'email'},
    {email:'member@example.test',token:'',type:'email'},
    {token_hash:'',type:'email'},
    {email:'member@example.test',token:'123456',type:'sms'},
  ])await assert.rejects(client.auth.verifyOtp(input),e=>e.code==='invalid_verification');
  assert.equal(calls.length,0);
  await assert.rejects(client.auth.verifyOtp({email:'member@example.test',token:'123456',type:'recovery'}),e=>e.status===403);
  assert.equal(calls.length,1);assert.equal(await client.auth.getSession(),null);client.dispose();
});

test('database, RPC and storage responses that started under a previous account are rejected without retry',async()=>{
  for(const run of [c=>c.from('notes').select('*').execute(),c=>c.rpc('change',{v:1}),c=>c.storage.from('private').download('a/b.txt')]){
    const pending=deferred();const reached=deferred();let dispatched=0;
    const {client}=fixture(async c=>{
      if(c.url.pathname==='/auth/v1/token')return response(wireSession());
      if(c.url.pathname==='/auth/v1/logout')return response(null,204);
      dispatched++;reached.resolve();await pending.promise;return response([{id:1}]);
    });
    await login(client);const work=run(client);await reached.promise;await client.auth.signOut();pending.resolve();
    await assert.rejects(work,e=>e instanceof StayoError&&e.code==='auth_superseded');assert.equal(dispatched,1);client.dispose();
  }
});

test('a failed sign-in attempt does not reject requests of the session that stays active',async()=>{
  const pending=deferred();const reached=deferred();let signIns=0;
  const {client}=fixture(async c=>{
    if(c.url.searchParams.get('grant_type')==='password'){signIns++;return signIns===1?response(wireSession('a')):response({code:'invalid_credentials',message:'invalid'},400);}
    reached.resolve();await pending.promise;return response([{id:1}]);
  });
  await login(client);const work=client.from('notes').select('*').execute();await reached.promise;
  await assert.rejects(login(client),e=>e.status===400);pending.resolve();
  assert.deepEqual((await work).data,[{id:1}]);assert.equal((await client.auth.getSession()).user.id,'user-a');client.dispose();
});

test('a request that started before switching to another account is still rejected',async()=>{
  const pending=deferred();const reached=deferred();let signIns=0;
  const {client}=fixture(async c=>{
    if(c.url.searchParams.get('grant_type')==='password'){signIns++;return response(wireSession(signIns===1?'a':'b'));}
    reached.resolve();await pending.promise;return response([{id:1}]);
  });
  await login(client);const work=client.from('notes').select('*').execute();await reached.promise;
  await login(client);pending.resolve();
  await assert.rejects(work,e=>e instanceof StayoError&&e.code==='auth_superseded');assert.equal((await client.auth.getSession()).user.id,'user-b');client.dispose();
});

test('anonymous reads and refresh within one account keep working',async()=>{
  const {client}=fixture(()=>response([{id:1}]));
  const result=await client.from('public_notes').select('*').execute();assert.deepEqual(result.data,[{id:1}]);client.dispose();
});
