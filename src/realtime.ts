import { HTTP, identifier } from './http.js';
import { StayoAuth } from './auth.js';
import { StayoError, type ClientOptions } from './types.js';
export type RealtimeStatus='connecting'|'subscribed'|'disconnected'|'resync-required'|'closed'|'error';
export interface PostgresChange {schema:string;table:string;type:'INSERT'|'UPDATE';record:Record<string,unknown>;old_record?:Record<string,unknown>;commit_timestamp?:string}
export interface SubscribeOptions {schema?:string;table:string;event?:'INSERT'|'UPDATE'|'*';filter?:string;onChange:(change:PostgresChange)=>void;onStatus?:(status:RealtimeStatus)=>void}
interface Message{topic:string;event:string;payload:Record<string,unknown>;ref?:string|null;join_ref?:string|null}
export class RealtimeSubscription {
  private socket:WebSocket|undefined;
  private stopped=false;
  private retry=0;
  private reference=0;
  private joinRef='';
  private heartbeatRef:string|undefined;
  private connectedBefore=false;
  private joined=false;
  private joinAcknowledged=false;
  private postgresReady=false;
  private heartbeat:ReturnType<typeof setInterval>|undefined;
  private joinTimer:ReturnType<typeof setTimeout>|undefined;
  private reconnect:ReturnType<typeof setTimeout>|undefined;
  private readonly offAuth:()=>void;
  private readonly topic:string;
  private readonly schema:string;
  constructor(private readonly http:HTTP,private readonly auth:StayoAuth,private readonly config:ClientOptions,private readonly opts:SubscribeOptions,private readonly onClosed:()=>void){
    this.schema=identifier(opts.schema??'public');identifier(opts.table);
    if(!['INSERT','UPDATE','*'].includes(opts.event??'*'))throw new StayoError('Only INSERT and UPDATE subscriptions are supported.','unsupported_event');
    this.topic=`realtime:stayo_${crypto.randomUUID()}`;
    this.offAuth=auth.onAuthStateChange((event,session)=>{
      if(event==='SIGNED_OUT'){this.unsubscribe();return;}
      if(this.socket?.readyState===1)this.send('access_token',{access_token:session?.accessToken??http.key});
    });
    void this.connect();
  }
  private status(value:RealtimeStatus):void{try{this.opts.onStatus?.(value);}catch{/* caller owns callback errors */}}
  private send(event:string,payload:Record<string,unknown>,topic=this.topic,ref=String(++this.reference)):string{
    this.socket?.send(JSON.stringify({topic,event,payload,ref,join_ref:topic===this.topic?this.joinRef:null}));return ref;
  }
  private markReady():void{
    if(this.joined||!this.joinAcknowledged||!this.postgresReady)return;
    this.joined=true;clearTimeout(this.joinTimer);this.retry=0;this.status('subscribed');
    if(this.connectedBefore)this.status('resync-required');this.connectedBefore=true;
  }
  private async connect():Promise<void>{
    if(this.stopped)return;
    this.status('connecting');
    try{
      await this.auth.accessToken();if(this.stopped)return;
      const u=new URL('/realtime/v1/websocket',this.http.origin);u.protocol=u.protocol==='https:'?'wss:':'ws:';u.search=new URLSearchParams({apikey:this.http.key,vsn:'1.0.0'}).toString();
      const socket=this.config.webSocketFactory?this.config.webSocketFactory(u.href):new WebSocket(u.href);this.socket=socket;
      socket.onopen=async()=>{
        let token:string|null;try{token=await this.auth.accessToken();}catch{socket.close();return;}
        if(this.stopped||this.socket!==socket)return;
        this.joinRef=String(++this.reference);
        const events=this.opts.event&&this.opts.event!=='*'?[this.opts.event]:['INSERT','UPDATE'];
        this.send('phx_join',{config:{broadcast:{self:false,ack:false},presence:{enabled:false},postgres_changes:events.map(event=>({event,schema:this.schema,table:this.opts.table,...(this.opts.filter?{filter:this.opts.filter}:{})}))},access_token:token??this.http.key},this.topic,this.joinRef);
        this.joinTimer=setTimeout(()=>socket.close(),this.config.realtime?.joinTimeoutMs??10000);
        this.heartbeat=setInterval(()=>{
          if(this.heartbeatRef){socket.close();return;}
          this.heartbeatRef=this.send('heartbeat',{},'phoenix');
        },this.config.realtime?.heartbeatMs??25000);
      };
      socket.onmessage=event=>{
        if(this.stopped||this.socket!==socket)return;
        let m:Message;try{m=JSON.parse(String(event.data)) as Message;}catch{return;}
        if(!m||typeof m!=='object'||typeof m.topic!=='string'||typeof m.event!=='string'||!m.payload||typeof m.payload!=='object')return;
        if(m.topic==='phoenix'&&m.event==='phx_reply'&&m.ref===this.heartbeatRef){this.heartbeatRef=undefined;return;}
        if(m.topic!==this.topic)return;
        if(m.event==='phx_reply'&&m.ref===this.joinRef){
          if(m.payload.status!=='ok'){this.status('error');socket.close();return;}
          this.joinAcknowledged=true;this.markReady();return;
        }
        if(m.event==='phx_error'||m.event==='phx_close'){socket.close();return;}
        if(m.event==='system'&&m.payload.status==='error'){this.status('error');socket.close();return;}
        if(m.event==='system'&&m.payload.extension==='postgres_changes'&&m.payload.status==='ok'){this.postgresReady=true;this.markReady();return;}
        if(m.event==='postgres_changes'&&this.joined&&(m.join_ref===undefined||m.join_ref===null||m.join_ref===this.joinRef)){
          const change=m.payload.data as PostgresChange|undefined;
          if(change&&['INSERT','UPDATE'].includes(change.type)&&change.schema===this.schema&&change.table===this.opts.table&&(this.opts.event===undefined||this.opts.event==='*'||change.type===this.opts.event)){
            try{this.opts.onChange(change);}catch{/* isolate application callbacks */}
          }
        }
      };
      socket.onerror=()=>{socket.close();};
      socket.onclose=()=>{if(this.socket!==socket)return;this.clearTimers();this.socket=undefined;if(!this.stopped){this.status('disconnected');this.retryConnection();}};
    }catch{if(!this.stopped){this.status('error');this.retryConnection();}}
  }
  private clearTimers():void{this.joined=false;this.joinAcknowledged=false;this.postgresReady=false;clearInterval(this.heartbeat);clearTimeout(this.joinTimer);this.heartbeatRef=undefined;}
  private retryConnection():void{
    if(this.stopped)return;const delays=this.config.realtime?.reconnectDelaysMs??[1000,2000,5000,10000,30000];
    const delay=delays[Math.min(this.retry++,delays.length-1)]??30000;
    this.reconnect=setTimeout(()=>{void this.connect();},delay);
  }
  unsubscribe():void{
    if(this.stopped)return;this.stopped=true;this.clearTimers();clearTimeout(this.reconnect);this.offAuth();
    if(this.socket?.readyState===1)this.send('phx_leave',{});
    this.socket?.close();this.socket=undefined;this.status('closed');this.onClosed();
  }
}
export class StayoRealtime{
  private readonly subscriptions=new Set<RealtimeSubscription>();
  private disposed=false;
  constructor(private readonly http:HTTP,private readonly auth:StayoAuth,private readonly config:ClientOptions){}
  subscribe(options:SubscribeOptions):RealtimeSubscription{if(this.disposed)throw new StayoError('Client has been disposed.','client_disposed');let subscription:RealtimeSubscription;subscription=new RealtimeSubscription(this.http,this.auth,this.config,options,()=>this.subscriptions.delete(subscription));this.subscriptions.add(subscription);return subscription;}
  removeAll():void{for(const subscription of this.subscriptions)subscription.unsubscribe();}
  dispose():void{this.disposed=true;this.removeAll();}
}
