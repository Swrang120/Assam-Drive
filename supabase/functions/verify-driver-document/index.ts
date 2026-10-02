import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{"content-type":"application/json"}});
const norm=(s:string)=>s.toLowerCase().normalize("NFKD").replace(/[^a-z0-9 ]/g," ").replace(/\s+/g," ").trim();
function similarity(a:string,b:string){
 const x=norm(a).split(" ").filter(Boolean), y=norm(b).split(" ").filter(Boolean);
 if(!x.length||!y.length)return 0;
 const ys=new Set(y); return x.filter(w=>ys.has(w)).length/Math.max(x.length,y.length)*100;
}
Deno.serve(async(req)=>{
 try{
  if(req.method!=="POST")return json({error:"POST required"},405);
  const auth=req.headers.get("Authorization")||"";
  const supabase=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_ANON_KEY")!,{global:{headers:{Authorization:auth}}});
  const {data:{user},error:ue}=await supabase.auth.getUser();
  if(ue||!user)return json({error:"Unauthorized"},401);
  const body=await req.json();
  const {document_id}=body;
  if(!document_id)return json({error:"document_id required"},400);
  const {data:doc,error:de}=await supabase.from("driver_documents").select("*").eq("id",document_id).single();
  if(de||!doc)return json({error:"Document not found"},404);
  if(doc.driver_id!==user.id)return json({error:"Forbidden"},403);
  const {data:driver}=await supabase.from("profiles").select("full_name").eq("id",user.id).single();
  if(!driver)return json({error:"Driver profile not found"},404);
  const {data:file,error:fe}=await supabase.storage.from("driver-documents").download(doc.storage_path);
  if(fe||!file)return json({error:"Could not read document from private storage"},500);

  // Provider is deliberately server-side. Set OCR_PROVIDER=google_vision and OCR_API_KEY
  // (or replace this adapter with Document AI) in Supabase secrets. Never expose these to the client.
  const provider=Deno.env.get("OCR_PROVIDER")||"";
  let ocrText="";
  if(provider==="google_vision"){
    const key=Deno.env.get("OCR_API_KEY");
    if(!key)return json({error:"OCR provider is not configured"},503);
    const bytes=new Uint8Array(await file.arrayBuffer());
    let binary=""; for(let i=0;i<bytes.length;i+=0x8000)binary+=String.fromCharCode(...bytes.subarray(i,i+0x8000));
    const content=btoa(binary);
    const vr=await fetch("https://vision.googleapis.com/v1/images:annotate?key="+encodeURIComponent(key),{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({requests:[{image:{content},features:[{type:"DOCUMENT_TEXT_DETECTION"}]}]})});
    if(!vr.ok)return json({error:"OCR provider failed"},502);
    const vd=await vr.json(); ocrText=vd.responses?.[0]?.fullTextAnnotation?.text||"";
  }else return json({error:"OCR provider not configured. Configure the server-side OCR provider before accepting documents."},503);

  const extractedName=ocrText.match(/(?:name|नाम)\s*[:\-]?\s*([A-Z][A-Z .'-]{3,})/i)?.[1]?.trim()||"";
  const score=similarity(driver.full_name||"",extractedName);
  const lower=ocrText.toLowerCase();
  const suspiciousTerms=["sample","specimen","demo","invalid","not valid","fake","photocopy only"];
  const suspicious=suspiciousTerms.some(x=>lower.includes(x));
  const status=suspicious?"SUSPICIOUS":(score>=70?"PASS":score>=45?"SUSPICIOUS":"FAILED");
  const {error}=await supabase.from("driver_documents").update({ocr_text:ocrText.slice(0,20000),extracted_name:extractedName,name_match_score:score,authenticity_status:status,automated_status:status==="PASS"?"MATCH":status==="FAILED"?"MISMATCH":"SUSPECTED"}).eq("id",document_id).eq("driver_id",user.id);
  if(error)return json({error:"Could not save verification result"},500);
  return json({ok:true,status,name_match_score:Math.round(score),extracted_name:extractedName});
 }catch(e){console.error(e);return json({error:"Verification service error"},500)}
});