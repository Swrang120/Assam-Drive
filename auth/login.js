/* Assam Drive Login — single click bridge */
window.AssamDriveAuth={
 open:function(intent){
   if(typeof window.openRoleChooser==='function') window.openRoleChooser(intent||'LOGIN');
   else alert('Login module is still starting. Please try again.');
 }
};
