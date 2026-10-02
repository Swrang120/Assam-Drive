/* Assam Drive Login — isolated, reliable mobile click controller */
(function(){
  function run(fn){
    try{ fn(); }catch(e){
      console.error('Assam Drive auth:',e);
      const s=document.getElementById('loginGateStatus');
      if(s)s.textContent='Please try again.';
    }
  }
  function login(){
    run(function(){
      if(typeof window.openRoleChooser==='function') window.openRoleChooser('LOGIN');
      else {
        const m=document.getElementById('authModal');
        if(m){m.classList.add('show');m.style.display='flex';m.style.pointerEvents='auto';}
      }
    });
  }
  function signup(){run(function(){
    if(typeof window.openRoleChooser==='function') window.openRoleChooser('SIGNUP');
  });}
  function forgot(){run(function(){
    if(typeof window.openForgotPassword==='function') window.openForgotPassword();
  });}
  window.AssamDriveAuth={open:login};
  window.AssamDriveCreateAccount={open:signup};
  window.AssamDriveRecovery={open:forgot};

  function bind(){
    const map=[
      ['loginStartBtn',login],
      ['createAccountBtn',signup],
      ['forgotPasswordBtn',forgot]
    ];
    map.forEach(function(pair){
      const el=document.getElementById(pair[0]);
      if(!el||el.dataset.assamAuthClick==='1')return;
      el.dataset.assamAuthClick='1';
      el.removeAttribute('onclick');
      el.addEventListener('click',function(e){
        e.preventDefault(); e.stopPropagation(); run(pair[1]);
      },false);
      el.addEventListener('touchend',function(e){
        e.preventDefault(); e.stopPropagation(); run(pair[1]);
      },{passive:false});
    });
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',bind);
  else bind();
})();