/* Assam Drive Forgot Password */
window.AssamDriveRecovery={open:function(){
 if(typeof window.openForgotPassword==='function') window.openForgotPassword();
 else alert('Password recovery module is still starting. Please try again.');
}};
