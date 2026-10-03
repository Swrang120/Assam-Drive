-- Assam Drive: secure account identity/role boundary
-- The dashboard role must come from public.profiles, never from a login
-- button or client-controlled requested_role value.

create or replace function public.get_my_account_role()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  uid uuid := auth.uid();
  result jsonb;
begin
  if uid is null then
    raise exception 'Not authenticated';
  end if;

  select jsonb_build_object(
    'id', p.id,
    'role', p.role,
    'full_name', p.full_name,
    'phone', p.phone,
    'email', p.email
  )
  into result
  from public.profiles p
  where p.id = uid;

  if result is null then
    raise exception 'Account profile not found';
  end if;

  return result;
end;
$$;

revoke execute on function public.get_my_account_role() from public;
grant execute on function public.get_my_account_role() to authenticated;

-- Rebuild the profile RPC so an existing account can never be silently
-- changed from CUSTOMER to DRIVER (or vice versa) by a client request.
create or replace function public.ensure_my_profile(
  p_role text,
  p_name text,
  p_phone text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  uid uuid := auth.uid();
  existing_role text;
  v_email text;
  result jsonb;
begin
  if uid is null then
    raise exception 'Not authenticated';
  end if;

  if p_role not in ('CUSTOMER','DRIVER') then
    raise exception 'Invalid role';
  end if;

  select role into existing_role
  from public.profiles
  where id = uid;

  if existing_role is not null and existing_role <> p_role then
    raise exception 'This account is registered as %; please use the correct login.', existing_role;
  end if;

  select lower(email) into v_email
  from auth.users
  where id = uid;

  if p_role = 'CUSTOMER' then
    if exists (
      select 1 from public.profiles
      where role = 'CUSTOMER'
        and id <> uid
        and lower(coalesce(email,'')) = lower(coalesce(v_email,''))
        and coalesce(v_email,'') <> ''
    ) then
      raise exception 'This Gmail is already registered as a customer account';
    end if;

    if exists (
      select 1 from public.profiles
      where role = 'CUSTOMER'
        and id <> uid
        and public.normalize_mobile(phone) = public.normalize_mobile(coalesce(p_phone,''))
        and public.normalize_mobile(coalesce(p_phone,'')) <> ''
    ) then
      raise exception 'This mobile number is already registered as a customer account';
    end if;
  end if;

  insert into public.profiles(id,role,full_name,phone,email,updated_at)
  values(uid,p_role,coalesce(p_name,''),coalesce(p_phone,''),v_email,now())
  on conflict(id) do update set
    full_name=excluded.full_name,
    phone=excluded.phone,
    email=excluded.email,
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
    'email',p.email,
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