import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
const json=(b:unknown,s=200)=>new Response(JSON.stringify(b),{status:s,headers:{"content-type":"application/json"}});
Deno.serve(async(req)=>{
 if(req.method!=="GET")return json({error:"GET required"},405);
 const auth=req.headers.get("Authorization")||"";
 const userClient=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_ANON_KEY")!,{global:{headers:{Authorization:auth}}});
 const {data:{user},error:ue}=await userClient.auth.getUser();
 if(ue||!user)return json({error:"Unauthorized"},401);
 const role=user.app_metadata?.role;
 if(role!=="ADMIN"&&role!=="SUPER_ADMIN")return json({error:"Admin access required"},403);
 const admin=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
 const [profiles,drivers,docs,rides,fares]=await Promise.all([
   admin.from("profiles").select("id,role,full_name,phone,created_at").order("created_at",{ascending:false}).limit(500),
   admin.from("driver_profiles").select("*").order("created_at",{ascending:false}).limit(500),
   admin.from("driver_documents").select("*").order("created_at",{ascending:false}).limit(1000),
   admin.from("rides").select("*").order("created_at",{ascending:false}).limit(1000),
   admin.from("fare_settings").select("*").order("vehicle_type")
 ]);
 const err=[profiles,drivers,docs,rides,fares].find(x=>x.error)?.error;
 if(err)return json({error:err.message},500);
 return json({profiles:profiles.data||[],drivers:drivers.data||[],documents:docs.data||[],rides:rides.data||[],fares:fares.data||[]});
});