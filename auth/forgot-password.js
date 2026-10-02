/* Assam Drive Forgot Password entry */
window.AssamDriveRecovery={open:function(){
  if(typeof window.openForgotPassword==='function') return window.openForgotPassword();
  const s=document.getElementById('loginGateStatus'); if(s)s.textContent='Password recovery module is still starting. Please try again.';
}};
