import { createClient } from '@supabase/supabase-js';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

const EMAIL_DOMAIN='@accounts.schedule-it.invalid';
const json=(statusCode,data,extra={})=>({statusCode,headers:{'content-type':'application/json','cache-control':'no-store',...extra},body:JSON.stringify(data)});
const hash=s=>createHash('sha256').update(s).digest('hex');
// Compare digests so neither length nor content of the bootstrap code leaks through timing.
const sameSecret=(a,b)=>timingSafeEqual(Buffer.from(hash(a),'hex'),Buffer.from(hash(b),'hex'));
const validUsername=s=>typeof s==='string'&&/^[a-z0-9_]{3,24}$/.test(s);
const validPassword=s=>typeof s==='string'&&s.length>=12&&Buffer.byteLength(s)<=128;
const validInvite=s=>typeof s==='string'&&s.length>0&&s.length<=256;
const isUuid=s=>typeof s==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
const client=()=>createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SECRET_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
const read=event=>{try{const v=JSON.parse(event.body||'{}');return v&&typeof v==='object'&&!Array.isArray(v)?v:null}catch{return null}};
const session=s=>({access_token:s.access_token,refresh_token:s.refresh_token,expires_at:s.expires_at});

// Thrown for unexpected backend failures; `stage` names the step so logs point at the root cause.
class StageError extends Error{constructor(stage,cause){super(stage);this.stage=stage;this.cause=cause}}
const fail=(stage,cause)=>{throw new StageError(stage,cause)};
// Only diagnostic fields: never request bodies, headers, tokens or keys.
const describe=e=>e&&({name:e.name,code:e.code,status:e.status,message:e.message,hint:e.hint,details:e.details});

// Detects the misconfigurations that otherwise surface as opaque "permission denied" errors.
function configProblem(){
 const {SUPABASE_URL:url,SUPABASE_SECRET_KEY:key}=process.env;
 if(!url||!key)return 'SUPABASE_URL or SUPABASE_SECRET_KEY is not set for this deploy context';
 let parsed;try{parsed=new URL(url)}catch{return 'SUPABASE_URL is not a valid URL'}
 if(parsed.protocol!=='https:'||parsed.pathname.replace(/\/$/,'')!=='')return 'SUPABASE_URL must be the bare project URL, e.g. https://<ref>.supabase.co';
 if(key!==key.trim())return 'SUPABASE_SECRET_KEY has leading/trailing whitespace';
 if(key.startsWith('sb_publishable_'))return 'SUPABASE_SECRET_KEY holds a publishable key; use the secret key (sb_secret_...)';
 const parts=key.split('.');
 if(parts.length===3){
  let role;try{role=JSON.parse(Buffer.from(parts[1],'base64url').toString()).role}catch{}
  if(role&&role!=='service_role')return `SUPABASE_SECRET_KEY is a legacy "${role}" JWT; use the service_role or sb_secret_ key`;
 }
 return null;
}
async function limit(db,event,action,max){
 const ip=(event.headers['x-nf-client-connection-ip']||'unknown').slice(0,128);
 const {data,error}=await db.rpc('check_auth_rate',{p_bucket:hash(action+':'+ip),p_limit:max,p_window_seconds:900});
 if(error)fail('rate limit ('+action+')',error);
 return data===true;
}
const bearer=event=>{const auth=event.headers.authorization||'';return auth.startsWith('Bearer ')?auth.slice(7):null};
async function userFromToken(db,token){
 if(!token)return null;
 const {data,error}=await db.auth.getUser(token);
 return error?null:data.user;
}
async function register(db,event,body){
 const {username,password,invite}=body;
 if(!validUsername(username)||!validPassword(password)||!validInvite(invite))return json(400,{error:'Invalid registration details'});
 if(!await limit(db,event,'register',10))return json(429,{error:'Too many attempts'});
 const bootstrap=process.env.BOOTSTRAP_INVITE_CODE;
 const isBootstrap=!!bootstrap&&sameSecret(invite,bootstrap);
 const inviteHash=isBootstrap?null:hash(invite);
 // Pre-checks avoid creating auth users for requests that cannot succeed; complete_registration re-checks atomically.
 if(isBootstrap){
  const {count,error}=await db.from('profiles').select('id',{count:'exact',head:true});
  if(error)fail('bootstrap profile count',error);
  if(count!==0)return json(403,{error:'Invitation invalid'});
 } else {
  const {data,error}=await db.from('invitations').select('id').eq('code_hash',inviteHash).is('used_at',null).is('revoked_at',null).gt('expires_at',new Date().toISOString()).maybeSingle();
  if(error)fail('invitation lookup',error);
  if(!data)return json(403,{error:'Invitation invalid'});
 }
 const {data:created,error:createError}=await db.auth.admin.createUser({email:username+EMAIL_DOMAIN,password,email_confirm:true});
 if(createError){
  if(createError.code==='email_exists'||createError.code==='user_already_exists')return json(409,{error:'Username unavailable'});
  if(createError.code==='weak_password')return json(400,{error:'Password rejected by the password policy'});
  fail('create auth user',createError);
 }
 const uid=created.user.id;
 const {data:outcome,error:rpcError}=await db.rpc('complete_registration',{p_user:uid,p_username:username,p_invite_hash:inviteHash,p_bootstrap:isBootstrap});
 if(rpcError||outcome!=='ok'){
  const {error:rollbackError}=await db.auth.admin.deleteUser(uid);
  if(rollbackError)console.error(JSON.stringify({level:'error',msg:'Registration rollback failed; orphan auth user',user_id:uid,error:describe(rollbackError)}));
  if(rpcError)fail('complete registration',rpcError);
  if(outcome==='username_taken')return json(409,{error:'Username unavailable'});
  return json(403,{error:'Invitation invalid'});
 }
 return json(201,{ok:true,role:isBootstrap?'admin':'user'});
}
async function handle(event,ref){
 const path=(event.path||'').split('/').pop();
 const problem=configProblem();
 if(path==='health'){
  if(problem)return json(503,{ok:false,stage:'config'});
  const {error}=await client().from('profiles').select('id',{head:true}).limit(1);
  if(error){console.error(JSON.stringify({level:'error',ref,stage:'health',error:describe(error)}));return json(503,{ok:false,stage:'database',ref})}
  return json(200,{ok:true});
 }
 if(event.httpMethod!=='POST')return json(405,{error:'Method not allowed'});
 if(Buffer.byteLength(event.body||'')>32768)return json(413,{error:'Request too large'});
 if(problem){console.error(JSON.stringify({level:'error',ref,stage:'config',problem}));return json(503,{error:'Server not configured',ref})}
 const body=read(event);
 if(!body)return json(400,{error:'Invalid JSON'});
 const db=client();
 if(path==='register')return register(db,event,body);
 if(path==='login'){
  const {username,password}=body;
  if(!validUsername(username)||typeof password!=='string'||Buffer.byteLength(password)>128)return json(401,{error:'Invalid credentials'});
  if(!await limit(db,event,'login',8))return json(429,{error:'Too many attempts'});
  const {data,error}=await client().auth.signInWithPassword({email:username+EMAIL_DOMAIN,password});
  if(error){
   if(error.code==='invalid_credentials')return json(401,{error:'Invalid credentials'});
   fail('sign in',error);
  }
  return json(200,session(data.session));
 }
 if(path==='refresh'){
  if(typeof body.refresh_token!=='string'||!body.refresh_token||body.refresh_token.length>512)return json(401,{error:'Session expired'});
  if(!await limit(db,event,'refresh',60))return json(429,{error:'Too many attempts'});
  const {data,error}=await client().auth.refreshSession({refresh_token:body.refresh_token});
  if(error||!data.session){
   if(error&&(error.status>=500||!error.status))fail('refresh session',error);
   return json(401,{error:'Session expired'});
  }
  return json(200,session(data.session));
 }
 const token=bearer(event);
 const user=await userFromToken(db,token);
 if(!user)return json(401,{error:'Login required'});
 if(path==='logout'){
  // Revokes this session's refresh token; the short-lived access token expires on its own.
  const {error}=await db.auth.admin.signOut(token,'local');
  if(error)console.error(JSON.stringify({level:'warn',ref,stage:'logout',error:describe(error)}));
  return json(200,{ok:true});
 }
 const {data:profile,error:profileError}=await db.from('profiles').select('username,role').eq('id',user.id).maybeSingle();
 if(profileError)fail('profile lookup',profileError);
 if(!profile)return json(403,{error:'Profile missing'});
 if(path==='me')return json(200,{username:profile.username,role:profile.role});
 if(path==='invitations'){
  if(profile.role!=='admin')return json(403,{error:'Admin only'});
  const code=randomBytes(24).toString('base64url');
  const {error}=await db.from('invitations').insert({code_hash:hash(code),created_by:user.id,expires_at:new Date(Date.now()+7*86400000).toISOString()});
  if(error)fail('create invitation',error);
  return json(201,{code,expires_in_days:7});
 }
 if(path==='blocks'){
  if(body.id!==undefined&&!isUuid(body.id))return json(400,{error:'Invalid block id'});
  if(body.action==='list'){
   const {data,error}=await db.from('calendar_blocks').select('id,payload').eq('user_id',user.id).limit(5000);
   if(error)fail('list blocks',error);
   return json(200,{blocks:data});
  }
  if(body.action==='upsert'&&body.payload&&typeof body.payload==='object'&&!Array.isArray(body.payload)){
   const record={user_id:user.id,payload:body.payload,updated_at:new Date().toISOString()};
   if(body.id){
    const {data,error}=await db.from('calendar_blocks').update(record).eq('id',body.id).eq('user_id',user.id).select('id').maybeSingle();
    if(error)fail('update block',error);
    return data?json(200,data):json(404,{error:'Block not found'});
   }
   const {data,error}=await db.from('calendar_blocks').insert(record).select('id').single();
   if(error)fail('insert block',error);
   return json(201,data);
  }
  if(body.action==='delete'&&body.id){
   const {data,error}=await db.from('calendar_blocks').delete().eq('id',body.id).eq('user_id',user.id).select('id');
   if(error)fail('delete block',error);
   return data.length?json(200,{ok:true}):json(404,{error:'Block not found'});
  }
  return json(400,{error:'Invalid action'});
 }
 return json(404,{error:'Unknown endpoint'});
}
export const handler=async event=>{
 const ref=randomUUID().slice(0,8);
 try{return await handle(event,ref)}
 catch(e){
  const stage=e instanceof StageError?e.stage:'unhandled';
  console.error(JSON.stringify({level:'error',ref,route:(event.path||'').split('/').pop(),stage,error:describe(e instanceof StageError?e.cause:e)}));
  return json(500,{error:'Server error',stage,ref});
 }
};
