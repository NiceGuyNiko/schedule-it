import { createClient } from '@supabase/supabase-js';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const json=(statusCode,data,extra={})=>({statusCode,headers:{'content-type':'application/json','cache-control':'no-store',...extra},body:JSON.stringify(data)});
const hash=s=>createHash('sha256').update(s).digest('hex');
const validUsername=s=>typeof s==='string'&&/^[a-z0-9_]{3,24}$/.test(s);
const validPassword=s=>typeof s==='string'&&s.length>=12&&Buffer.byteLength(s)<=128;
const client=()=>createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SECRET_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
const read=event=>{try{return JSON.parse(event.body||'{}')}catch{return null}};
async function limit(db,event,action){
 const ip=(event.headers['x-nf-client-connection-ip']||'unknown').slice(0,128);
 const bucket=hash(action+':'+ip);
 const {data,error}=await db.rpc('check_auth_rate',{p_bucket:bucket,p_limit:action==='login'?8:4,p_window_seconds:900});
 if(error)throw error;
 return data===true;
}
async function userFromToken(db,event){
 const auth=event.headers.authorization||'';
 if(!auth.startsWith('Bearer '))return null;
 const {data,error}=await db.auth.getUser(auth.slice(7));
 return error?null:data.user;
}
async function handle(event){
 if(event.httpMethod!=='POST')return json(405,{error:'Method not allowed'});
 if(Buffer.byteLength(event.body||'')>32768)return json(413,{error:'Request too large'});
 if(!process.env.SUPABASE_URL||!process.env.SUPABASE_SECRET_KEY)return json(503,{error:'Server not configured'});
 const path=(event.path||'').split('/').pop();
 const body=read(event);
 if(!body)return json(400,{error:'Invalid JSON'});
 const db=client();
 try {
  if(path==='register'){
   if(!await limit(db,event,'register'))return json(429,{error:'Too many attempts'});
   const {username,password,invite}=body;
   if(!validUsername(username)||!validPassword(password)||typeof invite!=='string')return json(400,{error:'Invalid registration details'});
   const bootstrap=process.env.BOOTSTRAP_INVITE_CODE;
   const isBootstrap=!!bootstrap&&typeof invite==='string'&&invite.length===bootstrap.length&&timingSafeEqual(Buffer.from(invite),Buffer.from(bootstrap));
   let invitation=null;
   if(isBootstrap){
    const {count}=await db.from('profiles').select('id',{count:'exact',head:true});
    if(count!==0)return json(403,{error:'Invitation invalid'});
   } else {
    const {data}=await db.from('invitations').select('*').eq('code_hash',hash(invite)).is('used_at',null).is('revoked_at',null).gt('expires_at',new Date().toISOString()).maybeSingle();
    if(!data)return json(403,{error:'Invitation invalid'});
    invitation=data;
   }
   const email=username+'@accounts.schedule-it.invalid';
   const {data:created,error:createError}=await db.auth.admin.createUser({email,password,email_confirm:true});
   if(createError)return json(409,{error:'Unable to register this username'});
   const uid=created.user.id;
   const {error:profileError}=await db.from('profiles').insert({id:uid,username,role:isBootstrap?'admin':'user'});
   if(profileError){await db.auth.admin.deleteUser(uid);return json(409,{error:'Username unavailable'});}
   if(invitation){
    const {data:claimed,error:claimError}=await db.rpc('claim_invitation',{p_hash:hash(invite),p_user:uid});
    if(claimError||!claimed){await db.auth.admin.deleteUser(uid);return json(409,{error:'Invitation already used'});}
   }
   return json(201,{ok:true});
  }
  if(path==='login'){
   if(!await limit(db,event,'login'))return json(429,{error:'Too many attempts'});
   const {username,password}=body;
   if(!validUsername(username)||typeof password!=='string')return json(401,{error:'Invalid credentials'});
   const authClient=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SECRET_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
   const {data,error}=await authClient.auth.signInWithPassword({email:username+'@accounts.schedule-it.invalid',password});
   if(error)return json(401,{error:'Invalid credentials'});
   return json(200,{access_token:data.session.access_token,refresh_token:data.session.refresh_token,expires_in:data.session.expires_in});
  }
  const user=await userFromToken(db,event);
  if(!user)return json(401,{error:'Login required'});
  const {data:profile}=await db.from('profiles').select('username,role').eq('id',user.id).single();
  if(!profile)return json(403,{error:'Profile missing'});
  if(path==='me')return json(200,{username:profile.username,role:profile.role});
  if(path==='invitations'){
   if(profile.role!=='admin')return json(403,{error:'Admin only'});
   const code=randomBytes(24).toString('base64url');
   const {error}=await db.from('invitations').insert({code_hash:hash(code),created_by:user.id,expires_at:new Date(Date.now()+7*86400000).toISOString()});
   if(error)throw error;
   return json(201,{code,expires_in_days:7});
  }
  if(path==='blocks'){
   if(body.action==='list'){
    const {data,error}=await db.from('calendar_blocks').select('id,payload').eq('user_id',user.id).limit(5000);
    if(error)throw error;
    return json(200,{blocks:data});
   }
   if(body.action==='upsert'&&body.payload&&typeof body.payload==='object'&&!Array.isArray(body.payload)){
    const record={user_id:user.id,payload:body.payload,updated_at:new Date().toISOString()};
    if(body.id&&/^[0-9a-f-]{36}$/i.test(body.id)){
     const {data,error}=await db.from('calendar_blocks').update(record).eq('id',body.id).eq('user_id',user.id).select('id').maybeSingle();
     if(error)throw error;
     return data?json(200,data):json(404,{error:'Block not found'});
    }
    const {data,error}=await db.from('calendar_blocks').insert(record).select('id').single();
    if(error)throw error;
    return json(201,data);
   }
   if(body.action==='delete'&&typeof body.id==='string'){
    const {error}=await db.from('calendar_blocks').delete().eq('id',body.id).eq('user_id',user.id);
    if(error)throw error;
    return json(200,{ok:true});
   }
   return json(400,{error:'Invalid action'});
  }
  return json(404,{error:'Unknown endpoint'});
 }catch(e){console.error('API error',e);return json(500,{error:'Server error'});}
}
export const handler=handle;
