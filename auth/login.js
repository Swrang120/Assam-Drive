const SUPABASE_URL='https://fvigmtojeywwyhfgyeww.supabase.co';
const SUPABASE_KEY='sb_publishable_DV1qmRyMo7kjtJxQ2JW_HA_rF9ACkuf';
const db=window.supabase.createClient(SUPABASE_URL,SUPABASE_KEY);
let role='';
const $=id=>document.getElementById(id);

document.querySelectorAll('[data-role]').forEach(b=>b.addEventListener('click',()=>{
  role=b.dataset.role;
  document.querySelectorAll('[data-role]').forEach(x=>x.classList.toggle('selected',x===b));
  $('role').classList.add('hidden');
  $('form').classList.remove('hidden');
  $('heading').textContent=(role==='DRIVER'?'Driver':'Customer')+' Login';
}));

$('change').onclick=()=>{
  role='';
  document.querySelectorAll('[data-role]').forEach(x=>x.classList.remove('selected'));
  $('form').classList.add('hidden');
  $('role').classList.remove('hidden');
  $('status').textContent='';
};

$('submit').onclick=async()=>{
  const email=$('email').value.trim().toLowerCase();
  const password=$('password').value;

  if(!/^\S+@\S+\.\S+$/.test(email)){
    $('status').textContent='Enter a valid Gmail/email address.';
    return;
  }
  if(!role){
    $('status').textContent='Choose Customer or Driver first.';
    return;
  }
  if(password.length<8){
    $('status').textContent='Password must be at least 8 characters.';
    return;
  }

  const btn=$('submit');
  btn.disabled=true;
  btn.textContent='Signing in…';
  $('status').textContent='Verifying your account…';

  try{
    const {data,error}=await db.auth.signInWithPassword({email,password});
    if(error)throw error;
    if(!data?.user||!data?.session)throw new Error('Login session was not created. Please try again.');

    // Tell index.html which dashboard to open after the redirect.
    localStorage.setItem('assam_drive_pending_role',role);

    // Keep the profile synced, but do not block login if this optional sync fails.
    const {error:profileError}=await db.rpc('ensure_my_profile',{
      p_role:role,
      p_name:data.user.user_metadata?.full_name||'',
      p_phone:data.user.user_metadata?.mobile_number||''
    });
    if(profileError)console.warn('Profile sync after login:',profileError.message);

    // Supabase has returned a real session; now open the authenticated app.
    const {data:check,error:checkError}=await db.auth.getSession();
    if(checkError||!check?.session)throw new Error('Login succeeded but the app session could not be restored. Please try again.');

    window.location.replace('../index.html?login=success');
  }catch(error){
    console.error('Assam Drive login error:',error);
    $('status').textContent=error?.message||'Login failed. Please try again.';
    btn.disabled=false;
    btn.textContent='🔐 Secure Login';
  }
};