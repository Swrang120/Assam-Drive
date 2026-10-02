/* Assam Drive Create Account entry */
window.AssamDriveCreateAccount={open:function(){
  if(typeof window.openRoleChooser==='function') return window.openRoleChooser('SIGNUP');
  const s=document.getElementById('loginGateStatus'); if(s)s.textContent='Create Account module is still starting. Please try again.';
}};
