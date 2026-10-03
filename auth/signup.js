document.addEventListener('DOMContentLoaded', () => {
  const SUPABASE_URL = 'https://fvigmtojeywwyhfgyeww.supabase.co';
  const SUPABASE_KEY = 'sb_publishable_DV1qmRyMo7kjtJxQ2JW_HA_rF9ACkuf';
  const db = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

  const params = new URLSearchParams(location.search);
  const role = params.get('role');
  const $ = id => document.getElementById(id);

  if (role !== 'CUSTOMER' && role !== 'DRIVER') {
    location.replace('./create-account.html');
    return;
  }

  $('roleLabel').textContent =
    role === 'DRIVER' ? '🚗 Driver Account' : '👤 Customer Account';

  const setStatus = msg => {
    $('status').textContent = msg || '';
  };

  $('phone').addEventListener('input', e => {
    e.target.value = e.target.value.replace(/\D/g, '').slice(0, 10);
  });

  $('otp').addEventListener('input', e => {
    e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
  });

  $('send').addEventListener('click', async () => {
    const name = $('name').value.trim();
    const phone = $('phone').value.replace(/\D/g, '');
    const email = $('email').value.trim().toLowerCase();

    if (name.length < 2) {
      setStatus('Please enter your full name.');
      $('name').focus();
      return;
    }

    if (phone.length !== 10) {
      setStatus('Please enter a valid 10-digit mobile number.');
      $('phone').focus();
      return;
    }

    if (!/^\S+@\S+\.\S+$/.test(email)) {
      setStatus('Please enter a valid Gmail/email address.');
      $('email').focus();
      return;
    }

    const button = $('send');
    button.disabled = true;
    button.textContent = 'Checking account…';
    setStatus('Checking Gmail and mobile number…');

    try {
      const check = await db.rpc('check_account_signup', {
        p_email: email,
        p_phone: '+91' + phone,
        p_role: role
      });

      if (check.error) throw check.error;

      if (!check.data?.allowed) {
        const reason = check.data?.reason;
        if (reason === 'EMAIL_EXISTS') {
          throw new Error('This Gmail is already registered. Please login. The same Gmail cannot be used for another account type.');
        }
        if (reason === 'PHONE_EXISTS') {
          throw new Error('This mobile number is already registered. Please login. It cannot be used for another account.');
        }
        throw new Error('This account information is already registered. Please login.');
      }

      button.textContent = 'Sending OTP…';
      setStatus('Sending verification OTP to ' + email + '…');

      const { error } = await db.auth.signInWithOtp({
        email,
        options: {
          shouldCreateUser: true,
          data: {
            requested_role: role,
            full_name: name,
            mobile_number: '+91' + phone
          }
        }
      });

      if (error) throw error;

      $('otpBox').classList.remove('hidden');
      setStatus('OTP sent to ' + email + '. Check Inbox and Spam/Junk.');
      $('otp').focus();
      button.textContent = '📩 OTP Sent — Resend';
      button.disabled = false;
    } catch (error) {
      console.error('OTP send error:', error);
      setStatus(error?.message || 'Account check/OTP failed. Please try again.');
      button.textContent = '📩 Send Gmail OTP';
      button.disabled = false;
    }
  });

  $('verify').addEventListener('click', async () => {
    const email = $('email').value.trim().toLowerCase();
    const token = $('otp').value.replace(/\D/g, '');

    if (token.length !== 6) {
      setStatus('Enter the 6-digit OTP received in Gmail.');
      $('otp').focus();
      return;
    }

    const button = $('verify');
    button.disabled = true;
    button.textContent = 'Verifying…';

    try {
      const { data, error } = await db.auth.verifyOtp({
        email,
        token,
        type: 'email'
      });

      if (error) throw error;
      if (!data?.user || !data?.session) {
        throw new Error('Verification did not create a valid account session. Please request a new OTP.');
      }

      $('passBox').classList.remove('hidden');
      $('otpBox').classList.add('hidden');
      setStatus('Gmail verified successfully. Now create your password.');
      $('pass').focus();
    } catch (error) {
      console.error('OTP verify error:', error);
      setStatus(error?.message || 'Invalid or expired OTP.');
      button.disabled = false;
      button.textContent = 'Verify Gmail';
    }
  });

  $('complete').addEventListener('click', async () => {
    const password = $('pass').value;
    const confirm = $('confirm').value;

    if (password.length < 8) {
      setStatus('Password must be at least 8 characters.');
      return;
    }

    if (password !== confirm) {
      setStatus('Passwords do not match.');
      return;
    }

    const button = $('complete');
    button.disabled = true;
    button.textContent = 'Creating account…';

    try {
      const { data, error } = await db.auth.updateUser({
        password,
        data: {
          requested_role: role,
          full_name: $('name').value.trim(),
          mobile_number: '+91' + $('phone').value.replace(/\D/g, '')
        }
      });

      if (error) throw error;
      if (!data?.user) throw new Error('Account session was not created. Please try again.');

      const profile = await db.rpc('ensure_my_profile', {
        p_role: role,
        p_name: $('name').value.trim(),
        p_phone: '+91' + $('phone').value.replace(/\D/g, '')
      });

      if (profile.error) throw profile.error;
      if (profile.data?.role !== role) {
        throw new Error('Account role verification failed. Please contact Assam Drive support.');
      }

      localStorage.setItem('assam_drive_pending_role', role);

      // Keep the verified Supabase session. index.html will read the backend
      // role and open exactly the matching Customer/Driver dashboard.
      location.replace('../index.html?login=success');
    } catch (error) {
      console.error('Account creation error:', error);
      setStatus(error?.message || 'Account could not be created.');
      button.disabled = false;
      button.textContent = 'Complete Account';
    }
  });
});