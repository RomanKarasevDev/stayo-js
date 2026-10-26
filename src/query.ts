import { HTTP, identifier } from './http.js';
import { StayoError, type RequestOptions } from './types.js';
export interface QueryResult<T> { data: T; count: number | null; status: number }
export type FilterOperator = 'eq'|'neq'|'gt'|'gte'|'lt'|'lte'|'like'|'ilike'|'is'|'in'|'cs'|'cd'|'ov';
export class Query<T = Record<string, unknown>> {
  private params = new URLSearchParams();
  private method = 'GET';
  private body: unknown;
  private headers: Record<string,string> = {};
  constructor(private readonly http: HTTP, private readonly path: string, private readonly schemaName = 'public') {}
  select(columns = '*', options: {count?: 'exact'|'planned'|'estimated'} = {}): this {
    this.params.set('select',columns); if (options.count) this.prefer(`count=${options.count}`); return this;
  }
  private prefer(value: string): void { this.headers.Prefer = [this.headers.Prefer,value].filter(Boolean).join(','); }
  insert(value: Partial<T>|readonly Partial<T>[]): this { this.method='POST';this.body=value;this.prefer('return=representation');return this; }
  upsert(value: Partial<T>|readonly Partial<T>[], options: {onConflict?: string} = {}): this { this.insert(value);this.prefer('resolution=merge-duplicates');if(options.onConflict)this.params.set('on_conflict',options.onConflict);return this; }
  update(value: Partial<T>): this { this.method='PATCH';this.body=value;this.prefer('return=representation');return this; }
  delete(): this { this.method='DELETE';this.prefer('return=representation');return this; }
  filter(column: string, operator: FilterOperator, value: string|number|boolean|null): this {
    identifier(column); if(!['eq','neq','gt','gte','lt','lte','like','ilike','is','in','cs','cd','ov'].includes(operator)) throw new StayoError('Invalid filter operator.','invalid_filter');
    this.params.append(column,`${operator}.${value}`);return this;
  }
  eq(column: string,value: string|number|boolean): this{return this.filter(column,'eq',value);}
  neq(column: string,value: string|number|boolean): this{return this.filter(column,'neq',value);}
  gt(column: string,value: string|number): this{return this.filter(column,'gt',value);}
  gte(column: string,value: string|number): this{return this.filter(column,'gte',value);}
  lt(column: string,value: string|number): this{return this.filter(column,'lt',value);}
  lte(column: string,value: string|number): this{return this.filter(column,'lte',value);}
  like(column: string,value: string): this{return this.filter(column,'like',value);}
  ilike(column: string,value: string): this{return this.filter(column,'ilike',value);}
  is(column: string,value: null|boolean): this{return this.filter(column,'is',value);}
  in(column: string,values: readonly (string|number|boolean)[]): this {
    const v=values.map(x=>typeof x==='string'?`"${x.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`:String(x)).join(',');
    return this.filter(column,'in',`(${v})`);
  }
  order(column: string,options: {ascending?:boolean;nullsFirst?:boolean} = {}): this {
    identifier(column); const value=`${column}.${options.ascending===false?'desc':'asc'}${options.nullsFirst===undefined?'':options.nullsFirst?'.nullsfirst':'.nullslast'}`;
    const current=this.params.get('order');this.params.set('order',current?`${current},${value}`:value);return this;
  }
  limit(count:number):this { if(!Number.isSafeInteger(count)||count<0)throw new StayoError('Invalid limit.','invalid_range');this.params.set('limit',String(count));return this; }
  range(from:number,to:number):this {
    if(!Number.isSafeInteger(from)||!Number.isSafeInteger(to)||from<0||to<from)throw new StayoError('Invalid row range.','invalid_range');
    this.headers.Range=`${from}-${to}`;this.headers['Range-Unit']='items';return this;
  }
  async execute(options:RequestOptions={}):Promise<QueryResult<T[]>> {
    const h={...this.headers,[this.method==='GET'?'Accept-Profile':'Content-Profile']:identifier(this.schemaName)};
    const res=await this.http.request(`${this.path}${this.params.size?'?'+this.params:''}`,{...options,method:this.method,headers:h,...(this.body===undefined?{}:{body:this.body})});
    const total=res.headers.get('Content-Range')?.split('/')[1];
    const data=res.status===204?[]:await res.json().catch(()=>{throw new StayoError('Invalid database response.','invalid_response',res.status);}) as T[];
    return {data,count:total&&/^\d+$/.test(total)?Number(total):null,status:res.status};
  }
}
export class Database {
  constructor(private readonly http:HTTP,private readonly schemaName='public') {identifier(schemaName);}
  from<T=Record<string,unknown>>(table:string):Query<T> {return new Query<T>(this.http,`/rest/v1/${identifier(table)}`,this.schemaName);}
  schema(name:string):Database{return new Database(this.http,name);}
  rpc<T=unknown>(name:string,args:Record<string,unknown>={},options:RequestOptions={}):Promise<T>{return this.http.json<T>(`/rest/v1/rpc/${identifier(name)}`,{...options,method:'POST',headers:{'Content-Profile':this.schemaName},body:args});}
}
