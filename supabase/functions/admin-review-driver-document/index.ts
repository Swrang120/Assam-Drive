import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
const json=(b:unknown,s=200)=>new Response(JSON.stringify(b),{status:s,headers:{"content-type":"application/json"}});
Deno.serve(async(req)=>{
 if(req.method!=="POST")return json({error:"POST required"},405);
 const auth=req.headers.get("Authorization")||"";
 const admin=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
 const userClient=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_ANON_KEY")!,{global:{headers:{Authorization:auth}}});
 const {data:{user},error}=await userClient.auth.getUser();
 if(error||!user)return json({error:"Unauthorized"},401);
 const role=user.app_metadata?.role;
 if(role!=="ADMIN"&&role!=="SUPER_ADMIN")return json({error:"Admin access required"},403);
 const body=await req.json(); const {document_id,decision,notes}=body;
 if(!document_id||!["APPROVED","REJECTED"].includes(decision))return json({error:"Invalid request"},400);
 const {data:doc,error:de}=await admin.from("driver_documents").select("id,driver_id").eq("id",document_id).single();
 if(de||!doc)return json({error:"Document not found"},404);
 const {error:up}=await admin.from("driver_documents").update({admin_status:decision,review_notes:notes||null,reviewed_by:user.id,reviewed_at:new Date().toISOString()}).eq("id",document_id);
 if(up)return json({error:"Could not update review"},500);
 if(decision==="APPROVED"){
   const {data:docs}=await admin.from("driver_documents").select("admin_status").eq("driver_id",doc.driver_id);
   const allApproved=!!docs?.length&&docs.every((x:any)=>x.admin_status==="APPROVED");
   if(allApproved)await admin.from("driver_profiles").update({verification_status:"APPROVED",verified:true}).eq("id",doc.driver_id);
 }
 return json({ok:true,decision});
});