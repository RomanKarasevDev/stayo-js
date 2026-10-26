import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createClient} from '../dist/index.js';

async function serve(handler){
  const server=createServer(handler);
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
  return {server,url:`http://127.0.0.1:${server.address().port}`,close:()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections()})};
}

test('native Fetch rejects redirects before any credential reaches the destination',async()=>{
  let leaked=0;const destination=await serve((req,res)=>{leaked++;res.end('{}')});
  const source=await serve((req,res)=>{res.writeHead(307,{Location:destination.url+'/stolen'});res.end()});
  const client=createClient({url:source.url,publicKey:'fixture-public'});
  try {await assert.rejects(client.from('notes').execute(),e=>e.code==='network_error');assert.equal(leaked,0);}
  finally {client.dispose();await source.close();await destination.close();}
});

test('deadline and caller cancellation include slow response-body consumption',async()=>{
  const source=await serve((req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.write('[')});
  const client=createClient({url:source.url,publicKey:'fixture-public'});
  try {
    await assert.rejects(client.from('notes').execute({timeoutMs:25}),e=>e.code==='aborted');
    const controller=new AbortController();const request=client.storage.from('photos').download('slow',{signal:controller.signal});setTimeout(()=>controller.abort(),25);await assert.rejects(request,e=>e.code==='aborted');
  } finally {client.dispose();await source.close();}
});
