import { HTTP, functionName } from './http.js';
import { StayoAuth } from './auth.js';
import { Database, type Query } from './query.js';
import { StayoStorage } from './storage.js';
import { StayoRealtime } from './realtime.js';
import { StayoError, type Capabilities, type ClientOptions, type RequestOptions } from './types.js';
export class StayoClient {
  readonly auth:StayoAuth;
  readonly storage:StayoStorage;
  readonly realtime:StayoRealtime;
  readonly functions:{invoke:<T=unknown>(name:string,options?:RequestOptions&{body?:unknown})=>Promise<T>};
  private readonly http:HTTP;
  private readonly database:Database;
  constructor(options:ClientOptions){
    this.http=new HTTP(options);this.auth=new StayoAuth(this.http,options);this.http.getToken=()=>this.auth.accessToken();this.http.getAuthGeneration=()=>this.auth.authGeneration();
    this.database=new Database(this.http);this.storage=new StayoStorage(this.http);this.realtime=new StayoRealtime(this.http,this.auth,options);
    this.functions={invoke:async<T=unknown>(name:string,opts:RequestOptions&{body?:unknown}={}):Promise<T>=>{
      functionName(name);
      const token=await this.auth.accessToken();if(!token)throw new StayoError('Sign in before invoking functions.','not_authenticated',401);
      const capabilities=await this.getCapabilities({...(opts.signal?{signal:opts.signal}:{}),...(opts.timeoutMs?{timeoutMs:opts.timeoutMs}:{})});
      if(capabilities?.protocol_version!==1||capabilities.runtime_version!=='1.3.0-compatible'||capabilities.capabilities?.functions!==true)throw new StayoError('Functions require a compatible Stayo runtime.','unsupported_capability',503);
      const currentToken=await this.auth.accessToken();if(!currentToken)throw new StayoError('Sign in before invoking functions.','not_authenticated',401);
      return this.http.json<T>(`/functions/v1/${name}`,{...opts,timeoutMs:opts.timeoutMs??65000,method:'POST',token:currentToken,...(opts.body===undefined?{}:{body:opts.body})});
    }};
  }
  from<T=Record<string,unknown>>(table:string):Query<T>{return this.database.from<T>(table);}
  schema(name:string):Database{return this.database.schema(name);}
  rpc<T=unknown>(name:string,args:Record<string,unknown>={},opts:RequestOptions={}):Promise<T>{return this.database.rpc<T>(name,args,opts);}
  getCapabilities(options:RequestOptions={}):Promise<Capabilities>{return this.http.json<Capabilities>('/.well-known/stayo.json',{...options,anonymous:true});}
  dispose():void{this.realtime.dispose();this.auth.dispose();this.http.dispose();}
}
export function createClient(options:ClientOptions):StayoClient{return new StayoClient(options);}
