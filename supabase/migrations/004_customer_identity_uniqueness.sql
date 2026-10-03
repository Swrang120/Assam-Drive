-- Assam Drive: global account identity lock
-- Apply this migration to the SAME Supabase project used by the website.
--
-- Supabase Auth already enforces unique email addresses in auth.users.
-- This migration adds a race-safe global mobile uniqueness rule and makes
-- Customer/Driver roles immutable.

begin;

create or replace function public.normalize_mobile(p_phone text)
returns text
language sql
immutable
as $$
  select case
    when p_phone is null then ''
    else right(regexp_replace(p_phone, '[^0-9]', '', 'g'), 10)
  end
$$;

-- Do not silently merge/delete old accounts. If old duplicate numbers exist,
-- the migration stops and they must be resolved first.
do $$
declare duplicate_count integer;
begin
  select count(*) into duplicate_count
  from (
    select public.normalize_mobile(phone) as phone_key
    from public.profiles
    where public.normalize_mobile(phone) <> ''
    group by public.normalize_mobile(phone)
    having count(*) > 1
  ) duplicates;

  if duplicate_count > 0 then
    raise exception 'Duplicate mobile numbers already exist in profiles. Resolve them before enabling the global mobile uniqueness rule.';
  end if;
end $$;

drop index if exists public.profiles_mobile_unique_idx;
drop index if exists public.profiles_customer_mobile_unique_idx;

create unique index profiles_mobile_unique_idx
on public.profiles (public.normalize_mobile(phone))
where public.normalize_mobile(phone) <> '';

-- A verified account's role is permanent. The same Auth user cannot become
-- Customer and Driver by changing profile data from the browser.
create or replace function public.prevent_profile_role_change()
returns trigger
language plpgsql
security definer
set search_path=public
as $$
begin
  if tg_op='UPDATE' and old.role <> new.role then
    raise exception 'Account role cannot be changed. This account is already registered as %.', old.role
      using errcode='P0001';
  end if;
  return new;
end;
$$;

drop trigger if exists profiles_role_immutable on public.profiles;
create trigger profiles_role_immutable
before update on public.profiles
for each row execute function public.prevent_profile_role_change();

-- Block a new Auth account when its signup metadata contains a mobile number
-- already owned by ANY existing Customer or Driver.
create or replace function public.prevent_duplicate_account_identity()
returns trigger
language plpgsql
security definer
set search_path=public
as $$
declare
  new_phone text;
  existing_id uuid;
begin
  new_phone := public.normalize_mobile(coalesce(new.raw_user_meta_data->>'mobile_number',''));

  -- Only enforce the mobile rule when this signup actually supplied one.
  if new_phone = '' then
    return new;
  end if;

  if length(new_phone) <> 10 then
    raise exception 'Mobile number must contain exactly 10 digits.'
      using errcode='P0001';
  end if;

  select p.id into existing_id
  from public.profiles p
  where public.normalize_mobile(p.phone)=new_phone
    and p.id<>new.id
  limit 1;

  if existing_id is not null then
    raise exception 'This mobile number is already registered to another Assam Drive account. Please log in instead.'
      using errcode='23505';
  end if;

  return new;
end;
$$;

drop trigger if exists prevent_duplicate_account_identity_auth_user on auth.users;
create trigger prevent_duplicate_account_identity_auth_user
before insert or update of raw_user_meta_data on auth.users
for each row execute function public.prevent_duplicate_account_identity();

-- Create the application profile in the same Auth transaction. This makes
-- the mobile unique index effective at account creation time, not only later
-- when the client calls ensure_my_profile.
create or replace function public.create_assam_drive_profile_for_auth_user()
returns trigger
language plpgsql
security definer
set search_path=public
as $
declare
  requested_role text := upper(coalesce(new.raw_user_meta_data->>'requested_role',''));
  clean_phone text := public.normalize_mobile(coalesce(new.raw_user_meta_data->>'mobile_number',''));
  clean_name text := coalesce(new.raw_user_meta_data->>'full_name','');
begin
  if requested_role not in ('CUSTOMER','DRIVER') then
    return new;
  end if;

  if clean_phone='' or length(clean_phone)<>10 then
    raise exception 'A valid 10-digit mobile number is required for Assam Drive signup.'
      using errcode='23514';
  end if;

  insert into public.profiles(id,role,full_name,phone,updated_at)
  values(new.id,requested_role,clean_name,clean_phone,now());

  if requested_role='DRIVER' then
    insert into public.driver_profiles(id,vehicle_type,updated_at)
    values(new.id,'BIKE',now())
    on conflict(id) do nothing;
  end if;

  return new;
end;
$;

drop trigger if exists create_assam_drive_profile_on_auth_user on auth.users;
create trigger create_assam_drive_profile_on_auth_user
after insert on auth.users
for each row execute function public.create_assam_drive_profile_for_auth_user();

-- Backend role/identity check used by both signup and login.
create or replace function public.check_account_signup(
  p_email text,
  p_phone text,
  p_role text
)
returns jsonb
language plpgsql
security definer
set search_path=public
as $$
declare
  clean_email text := lower(trim(coalesce(p_email,'')));
  clean_phone text := public.normalize_mobile(p_phone);
  existing_user uuid;
  existing_profile_role text;
begin
  if p_role not in ('CUSTOMER','DRIVER') then
    raise exception 'Invalid account role';
  end if;

  if clean_email='' or clean_phone='' or length(clean_phone)<>10 then
    return jsonb_build_object('allowed',false,'reason','INVALID_IDENTITY');
  end if;

  select id into existing_user
  from auth.users
  where lower(email)=clean_email
  limit 1;

  if existing_user is not null then
    select role into existing_profile_role
    from public.profiles
    where id=existing_user;

    return jsonb_build_object(
      'allowed',false,
      'reason','EMAIL_EXISTS',
      'role',existing_profile_role
    );
  end if;

  if exists(
    select 1 from public.profiles
    where public.normalize_mobile(phone)=clean_phone
  ) then
    return jsonb_build_object('allowed',false,'reason','PHONE_EXISTS');
  end if;

  return jsonb_build_object('allowed',true);
end;
$$;

grant execute on function public.check_account_signup(text,text,text) to anon,authenticated;

create or replace function public.check_customer_signup(
  p_email text,
  p_phone text
)
returns jsonb
language sql
security definer
set search_path=public
as $$
  select public.check_account_signup(p_email,p_phone,'CUSTOMER')
$$;

grant execute on function public.check_customer_signup(text,text) to anon,authenticated;

create or replace function public.get_my_account_role()
returns jsonb
language plpgsql
security definer
set search_path=public
as $$
declare
  uid uuid := auth.uid();
  result jsonb;
begin
  if uid is null then
    raise exception 'Not authenticated';
  end if;

  select jsonb_build_object(
    'id',p.id,
    'role',p.role,
    'full_name',p.full_name,
    'phone',p.phone
  )
  into result
  from public.profiles p
  where p.id=uid;

  return coalesce(result,jsonb_build_object('role',null));
end;
$$;

grant execute on function public.get_my_account_role() to authenticated;

-- Single source of truth for profile creation after OTP/password verification.
-- It rejects role changes and duplicate mobile numbers server-side.
create or replace function public.ensure_my_profile(
  p_role text,
  p_name text,
  p_phone text
)
returns jsonb
language plpgsql
security definer
set search_path=public
as $$
declare
  uid uuid := auth.uid();
  clean_phone text := public.normalize_mobile(p_phone);
  existing_role text;
  existing_id uuid;
  result jsonb;
begin
  if uid is null then
    raise exception 'Not authenticated';
  end if;

  if p_role not in ('CUSTOMER','DRIVER') then
    raise exception 'Invalid role';
  end if;

  if clean_phone='' or length(clean_phone)<>10 then
    raise exception 'Mobile number must contain exactly 10 digits.';
  end if;

  select role into existing_role
  from public.profiles
  where id=uid
  for update;

  if existing_role is not null and existing_role <> p_role then
    raise exception 'This Gmail account is already registered as %. The same Gmail cannot be used for another account type.', existing_role;
  end if;

  select id into existing_id
  from public.profiles
  where public.normalize_mobile(phone)=clean_phone
    and id<>uid
  limit 1;

  if existing_id is not null then
    raise exception 'This mobile number is already registered to another Assam Drive account. Please log in instead.'
      using errcode='23505';
  end if;

  insert into public.profiles(id,role,full_name,phone,updated_at)
  values(uid,p_role,coalesce(p_name,''),clean_phone,now())
  on conflict(id) do update set
    full_name=excluded.full_name,
    phone=excluded.phone,
    updated_at=now();

  if p_role='DRIVER' then
    insert into public.driver_profiles(id,vehicle_type,updated_at)
    values(uid,'BIKE',now())
    on conflict(id) do nothing;
  end if;

  select jsonb_build_object(
    'id',p.id,
    'role',p.role,
    'full_name',p.full_name,
    'phone',p.phone,
    'driver',case when p.role='DRIVER'
      then (select to_jsonb(d) from public.driver_profiles d where d.id=p.id)
      else null end
  )
  into result
  from public.profiles p
  where p.id=uid;

  return result;
end;
$$;

grant execute on function public.ensure_my_profile(text,text,text) to authenticated;

revoke all on function public.normalize_mobile(text) from public;
revoke all on function public.prevent_profile_role_change() from public;
revoke all on function public.prevent_duplicate_account_identity() from public;

commit;