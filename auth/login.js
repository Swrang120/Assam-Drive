/* Assam Drive Login bridge */
/* Assam Drive auth click bridge — keeps mobile auth buttons callable even if inline handlers are restricted. */
window.assamDriveAuth=function(intent){
  try{
    const m=document.getElementById('authModal');
    if(m){m.classList.add('show');m.style.display='flex';m.style.pointerEvents='auto';m.setAttribute('aria-hidden','false');}
    if(typeof window.openRoleChooser==='function') return window.openRoleChooser(intent||'LOGIN');
    if(typeof openRoleChooser==='function') return openRoleChooser(intent||'LOGIN');
    const s=document.getElementById('loginGateStatus');
    if(s)s.textContent='Login module is still starting. Please tap again.';
  }catch(e){
    console.error('Auth button error:',e);
    const s=document.getElementById('loginGateStatus');
    if(s)s.textContent='Please try again. '+(e?.message||'Authentication module error');
  }
};
window.assamDriveForgotPassword=function(){
  try{
    if(typeof window.openForgotPassword==='function') return window.openForgotPassword();
    if(typeof openForgotPassword==='function') return openForgotPassword();
  }catch(e){
    console.error('Forgot password error:',e);
  }
};
