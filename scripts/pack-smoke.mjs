import {mkdtemp,writeFile,readFile,rm,stat} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join,dirname,resolve,basename} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {spawnSync} from 'node:child_process'
import {createRequire} from 'node:module'
import {createServer} from 'node:http'
import assert from 'node:assert/strict'
const root=join(dirname(fileURLToPath(import.meta.url)),'..')
const temp=await mkdtemp(join(tmpdir(),'stayo-js-pack-'))
const servers=[]
const args=process.argv.slice(2)
assert.ok(args.length===0||(args.length===2&&args[0]==='--tarball'),'usage: pack-smoke.mjs [--tarball archive.tgz]')
const supplied=args.length?resolve(args[1]):null
function run(command,args,cwd=root){
  const r=spawnSync(command,args,{cwd,encoding:'utf8',env:process.env})
  if(r.status!==0)throw new Error(`${command} failed: ${r.stderr||r.stdout}`)
  return r.stdout
}
async function fixture(project){
  const notes=[];const objects=new Map();let functionCalls=0
  const server=createServer(async(req,res)=>{
    try {
      const url=new URL(req.url,'http://localhost');const path=url.pathname
      if(req.headers.apikey!==`${project}-public`){res.writeHead(401);res.end('{}');return}
      const chunks=[];for await(const c of req)chunks.push(c);const bytes=Buffer.concat(chunks)
      const body=bytes.length&&req.headers['content-type']?.includes('json')?JSON.parse(bytes):null
      const bearer=req.headers.authorization?.replace('Bearer ','')
      const user=bearer?.startsWith(`${project}-access-`)?bearer.slice(`${project}-access-`.length):null
      const json=(data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(data))}
      if(path==='/auth/v1/token'){
        const userId=body.email==='second@example.test'?'second':'first'
        json({access_token:`${project}-access-${userId}`,refresh_token:`${project}-refresh-${userId}`,expires_in:3600,user:{id:userId}});return
      }
      if(path==='/auth/v1/user'){json({id:user});return}
      if(path==='/auth/v1/logout'){res.writeHead(204);res.end();return}
      if(path==='/.well-known/stayo.json'){json({protocol_version:1,runtime_version:'1.3.0-compatible',capabilities:{auth:true,database:true,storage:true,functions:true,realtime:true}});return}
      if(!user){json({code:'not_authenticated'},401);return}
      if(path==='/rest/v1/notes'){
        if(req.method==='POST'){
          if(body.owner_id&&body.owner_id!==user){json({code:'rls_denied'},403);return}
          const note={id:notes.length+1,...body,owner_id:user};notes.push(note);json([note]);return
        }
        json(notes.filter(n=>n.owner_id===user));return
      }
      if(path==='/rest/v1/rpc/count_notes'){json(notes.filter(n=>n.owner_id===user).length);return}
      if(path.startsWith('/storage/v1/object/sign/')){json({signedURL:`/object/sign/photos/file?token=${project}-signed`});return}
      if(path.startsWith('/storage/v1/object/photos/')){
        if(req.method==='POST'){objects.set(`${user}:${path}`,bytes);json({Key:'photos/file'});return}
        const object=objects.get(`${user}:${path}`);if(!object){json({code:'not_found'},404);return}
        res.writeHead(200,{'Content-Type':'text/plain'});res.end(object);return
      }
      if(path==='/storage/v1/object/photos'&&req.method==='DELETE'){for(const prefix of body.prefixes)objects.delete(`${user}:/storage/v1/object/photos/${prefix}`);json([]);return}
      if(path==='/functions/v1/echo'){functionCalls++;json({user,body:body,project});return}
      if(path==='/functions/v1/overloaded'){functionCalls++;json({error:{code:'FUNCTION_CONCURRENCY_LIMIT',message:'fixture-provider-secret'}},429);return}
      json({code:'not_found'},404)
    }catch{res.writeHead(500);res.end('{}')}
  })
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)})
  servers.push(server)
  return {url:`http://127.0.0.1:${server.address().port}`,publicKey:`${project}-public`,calls:()=>functionCalls}
}
try {
  if(!supplied)run('npm',['run','build'])
  const pack=supplied?{
    filename:basename(supplied),size:(await stat(supplied)).size,
    files:run('tar',['-tf',supplied]).trim().split('\n').map(path=>({path:path.replace(/^package\//,'')})),
  }:JSON.parse(run('npm',['pack','--json','--ignore-scripts','--pack-destination',temp]))[0]
  assert.ok(pack.files.some(f=>f.path==='dist/index.d.ts'))
  assert.ok(!pack.files.some(f=>f.path.startsWith('src/')||f.path.startsWith('node_modules/')||f.path.includes('.env')))
  await writeFile(join(temp,'package.json'),JSON.stringify({name:'stayo-pack-consumer',private:true,type:'module'}))
  run('npm',['install','--offline','--ignore-scripts','--no-audit','--no-fund','--package-lock=false',supplied??join(temp,pack.filename)],temp)
  const require=createRequire(join(temp,'package.json'))
  const {createClient,MemoryStorage}=await import(pathToFileURL(require.resolve('@stayo/sdk')).href)
  const packageMetadata=JSON.parse(await readFile(join(temp,'node_modules/@stayo/sdk/package.json'),'utf8'))
  assert.equal(packageMetadata.version,'0.1.0');assert.equal(Object.keys(packageMetadata.dependencies??{}).length,0)
  await writeFile(join(temp,'consumer.ts'),`import {createClient, type StorageAdapter, type Session} from '@stayo/sdk';\nconst c=createClient({url:'https://project.example',publicKey:'public'});\nconst result=c.from<{id:number}>('notes').select().eq('id',1).execute();\nconst session:Promise<Session|null>=c.auth.getSession();\nconst verified=c.auth.verifyOtp({email:'member@example.test',token:'123456',type:'email'});\nvoid result; void session; void verified; c.dispose();\n`)
  run('tsc',['--noEmit','--strict','--module','NodeNext','--target','ES2022','--lib','ES2022,DOM,DOM.Iterable',join(temp,'consumer.ts')],temp)
  const project1=await fixture('one');const project2=await fixture('two');const storage=new MemoryStorage()
  const first=createClient({...project1,storage,storageNamespace:'first'})
  const second=createClient({...project1,storage,storageNamespace:'second'})
  const separate=createClient({...project2,storage,storageNamespace:'first'})
  try {
    await first.auth.signInWithPassword({email:'first@example.test',password:'test'})
    await second.auth.signInWithPassword({email:'second@example.test',password:'test'})
    await separate.auth.signInWithPassword({email:'first@example.test',password:'test'})
    await first.from('notes').insert({title:'First private note'}).execute()
    assert.equal((await first.from('notes').select().execute()).data.length,1)
    assert.deepEqual((await second.from('notes').select().execute()).data,[])
    assert.deepEqual((await separate.from('notes').select().execute()).data,[])
    await assert.rejects(first.from('notes').insert({title:'Forbidden',owner_id:'second'}).execute(),e=>e.status===403)
    assert.equal(await first.rpc('count_notes'),1)
    const bucket=first.storage.from('photos')
    await bucket.upload('file',new Blob(['packed artifact']))
    assert.equal(await (await bucket.download('file')).text(),'packed artifact')
    await assert.rejects(second.storage.from('photos').download('file'),e=>e.status===404)
    assert.ok((await bucket.createSignedUrl('file',60)).startsWith(project1.url+'/storage/v1/object/sign/'))
    await bucket.remove(['file'])
    const invoked=await first.functions.invoke('echo',{body:{message:'hello'}})
    assert.deepEqual(invoked,{user:'first',body:{message:'hello'},project:'one'});assert.equal(project1.calls(),1)
    await assert.rejects(first.functions.invoke('overloaded'),e=>e.status===429&&e.code==='FUNCTION_CONCURRENCY_LIMIT'&&!String(e).includes('fixture-provider-secret'))
    assert.equal(project1.calls(),2)
    await first.auth.signOut();assert.equal(await first.auth.getSession(),null)
    console.log(JSON.stringify({package:pack.filename,version:packageMetadata.version,bytes:pack.size,networkFixture:'passed',twoUsersTwoProjects:'passed',declarations:'passed',registryPublished:false}))
  } finally {first.dispose();second.dispose();separate.dispose()}
} finally {
  for(const server of servers)await new Promise(resolve=>{server.close(resolve);server.closeAllConnections()})
  await rm(temp,{recursive:true,force:true})
}
