import { HTTP, bucketName, objectPath } from './http.js';
import { StayoError, type RequestOptions } from './types.js';
export class StorageBucket {
  private readonly bucket:string;
  constructor(private readonly http:HTTP,name:string){this.bucket=bucketName(name);}
  upload<T=unknown>(path:string,data:Blob|ArrayBuffer|Uint8Array,options:RequestOptions&{contentType?:string;upsert?:boolean}={}):Promise<T>{
    return this.http.json<T>(`/storage/v1/object/${this.bucket}/${objectPath(path)}`,{...options,method:'POST',rawBody:data as BodyInit,headers:{'Content-Type':options.contentType??(data instanceof Blob&&data.type?data.type:'application/octet-stream'),'x-upsert':String(options.upsert??false)}});
  }
  async download(path:string,options:RequestOptions={}):Promise<Blob>{return (await this.http.request(`/storage/v1/object/${this.bucket}/${objectPath(path)}`,options)).blob();}
  remove<T=unknown>(paths:readonly string[],options:RequestOptions={}):Promise<T>{for(const path of paths)objectPath(path);return this.http.json<T>(`/storage/v1/object/${this.bucket}`,{...options,method:'DELETE',body:{prefixes:paths}});}
  async createSignedUrl(path:string,expiresIn:number,options:RequestOptions={}):Promise<string>{
    if(!Number.isSafeInteger(expiresIn)||expiresIn<1)throw new StayoError('Invalid signed URL lifetime.','invalid_expiry');
    const r=await this.http.json<{signedURL?:string;signedUrl?:string}>(`/storage/v1/object/sign/${this.bucket}/${objectPath(path)}`,{...options,method:'POST',body:{expiresIn}});
    const value=r.signedURL??r.signedUrl;
    if(typeof value!=='string'||value.startsWith('//')||value.includes('\\'))throw new StayoError('Invalid signed URL.','invalid_redirect');
    const u=new URL(value.startsWith('/object/')?`/storage/v1${value}`:value,this.http.origin);
    if(u.origin!==this.http.origin||u.username||u.password||u.hash||!u.pathname.startsWith('/storage/v1/object/sign/'))throw new StayoError('Signed URL left the project boundary.','invalid_redirect');
    return u.href;
  }
}
export class StayoStorage {constructor(private readonly http:HTTP){}from(bucket:string):StorageBucket{return new StorageBucket(this.http,bucket);}}
