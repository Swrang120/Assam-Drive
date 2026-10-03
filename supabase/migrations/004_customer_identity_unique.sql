-- Assam Drive customer identity protection
-- Customer email + mobile are stored in profiles and enforced as unique identities.

alter table public.profiles
  add column if not exists email text;

update public.profiles p
set email = lower(u.email)
from auth.users u
where u.id = p.id
  and p.email is null
  and u.email is not null;

create unique index if not exists profiles_customer_email_unique
  on public.profiles (lower(email))
  where role = 'CUSTOMER' and email is not null and email <> '';

create unique index if not exists profiles_customer_phone_unique
  on public.profiles (phone)
  where role = 'CUSTOMER' and phone is not null and phone <> '';

-- Public signup pre-check. It returns only whether the supplied identity
-- can start a NEW customer signup; it does not expose profile rows.
create or replace function public.check_customer_signup(
  p_email text,
  p_phone text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_email text := lower(trim(coalesce(p_email,'')));
  v_phone text := trim(coalesce(p_phone,''));
begin
  if v_email = '' or v_phone = '' then
    return jsonb_build_object('allowed', false, 'reason', 'INVALID_INPUT');
  end if;

  if exists (
    select 1
    from public.profiles
    where role = 'CUSTOMER'
      and lower(coalesce(email,'')) = v_email
  ) then
    return jsonb_build_object('allowed', false, 'reason', 'EMAIL_EXISTS');
  end if;

  if exists (
    select 1
    from public.profiles
    where role = 'CUSTOMER'
      and phone = v_phone
  ) then
    return jsonb_build_object('allowed', false, 'reason', 'PHONE_EXISTS');
  end if;

  if exists (
    select 1
    from auth.users
    where lower(coalesce(email,'')) = v_email
  ) then
    return jsonb_build_object('allowed', false, 'reason', 'EMAIL_EXISTS');
  end if;

  return jsonb_build_object('allowed', true);
end;
$$;

revoke execute on function public.check_customer_signup(text,text) from public;
grant execute on function public.check_customer_signup(text,text) to anon, authenticated;

-- Keep the existing 3-argument function signature used by the app,
-- while automatically storing the Auth email and rejecting duplicate
-- customer email/mobile values at the database boundary.
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
  v_email text;
  result jsonb;
begin
  if uid is null then
    raise exception 'Not authenticated';
  end if;

  if p_role not in ('CUSTOMER','DRIVER') then
    raise exception 'Invalid role';
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
        and phone = coalesce(p_phone,'')
        and coalesce(p_phone,'') <> ''
    ) then
      raise exception 'This mobile number is already registered as a customer account';
    end if;
  end if;

  insert into public.profiles(id,role,full_name,phone,email,updated_at)
  values(uid,p_role,coalesce(p_name,''),coalesce(p_phone,''),v_email,now())
  on conflict(id) do update set
    role=excluded.role,
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
    'driver',
      case when p.role='DRIVER'
        then (select to_jsonb(d) from public.driver_profiles d where d.id=p.id)
        else null
      end
  )
  into result
  from public.profiles p
  where p.id=uid;

  return result;
end;
$$;
