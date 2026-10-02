document.addEventListener('DOMContentLoaded',()=>{
const URL='https://fvigmtojeywwyhfgyeww.supabase.co';
const KEY='sb_publishable_DV1qmRyMo7kjtJxQ2JW_HA_rF9ACkuf';
const db=window.supabase.createClient(URL,KEY);
let role=new URLSearchParams(location.search).get('role')||'';
const $=id=>document.getElementById(id);
const status=msg=>{$('status').textContent=msg||''};

document.querySelectorAll('[data-role]').forEach(button=>{
 button.addEventListener('click',()=>{
  role=button.dataset.role;
  document.querySelectorAll('[data-role]').forEach(b=>b.classList.remove('selected'));
  button.classList.add('selected');
  $('roleStep').classList.add('hidden');
  $('form').classList.remove('hidden');
  $('selectedRole').textContent=role==='DRIVER'?'🚗 Driver account selected':'👤 Customer account selected';
  $('name').focus();
 });
});

$('change').addEventListener('click',()=>{
 role='';
 $('form').classList.add('hidden');
 $('roleStep').classList.remove('hidden');
 $('status').textContent='';
 document.querySelectorAll('[data-role]').forEach(b=>b.classList.remove('selected'));
});

$('phone').addEventListener('input',e=>{e.target.value=e.target.value.replace(/\D/g,'').slice(0,10)});
$('otp').addEventListener('input',e=>{e.target.value=e.target.value.replace(/\D/g,'').slice(0,6)});

$('send').addEventListener('click',async()=>{
 const name=$('name').value.trim(),phone=$('phone').value.replace(/\D/g,''),email=$('email').value.trim().toLowerCase();
 if(!role){status('Select Customer or Driver first.');return}
 if(name.length<2||phone.length!==10||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){status('Enter valid name, 10-digit mobile and email.');return}
 const button=$('send');button.disabled=true;button.textContent='Sending OTP…';
 const {error}=await db.auth.signInWithOtp({email,options:{data:{requested_role:role,full_name:name,mobile_number:'+91'+phone}}});
 if(error){status(error.message);button.disabled=false;button.textContent='📩 Send Gmail OTP';return}
 $('otpBox').classList.remove('hidden');status('OTP sent to '+email+'.');
});

$('verify').addEventListener('click',async()=>{
 const email=$('email').value.trim().toLowerCase(),token=$('otp').value.replace(/\D/g,'');
 if(token.length!==6){status('Enter the 6-digit OTP.');return}
 const {data,error}=await db.auth.verifyOtp({email,token,type:'email'});
 if(error){status(error.message);return}
 if(!data.user){status('Verification failed.');return}
 $('passBox').classList.remove('hidden');$('otpBox').classList.add('hidden');status('Gmail verified. Create your password.');
 $('pass').focus();
});

$('complete').addEventListener('click',async()=>{
 const p=$('pass').value,q=$('confirm').value;
 if(p.length<8||p!==q){status(p.length<8?'Password must be at least 8 characters.':'Passwords do not match.');return}
 const button=$('complete');button.disabled=true;button.textContent='Creating account…';
 const {error}=await db.auth.updateUser({password:p,data:{requested_role:role,full_name:$('name').value.trim(),mobile_number:'+91'+$('phone').value.replace(/\D/g,'')}});
 if(error){status(error.message);button.disabled=false;button.textContent='Complete Account';return}
 await db.auth.signOut();
 location.href='./login.html';
});
});