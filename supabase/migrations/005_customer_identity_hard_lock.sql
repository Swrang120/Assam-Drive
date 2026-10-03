-- Assam Drive: hard customer identity lock
-- Enforces one customer identity per email + Indian mobile number at DB level.
-- Safe to run after the core profiles migration.

alter table public.profiles
  add column if not exists email text;

update public.profiles p
set email = lower(trim(u.email))
from auth.users u
where u.id = p.id
  and (p.email is null or trim(p.email) = '')
  and u.email is not null;

-- Canonical Indian mobile key:
-- +91XXXXXXXXXX, 91XXXXXXXXXX and XXXXXXXXXX resolve to the same 10 digits.
alter table public.profiles
  add column if not exists customer_phone_key text
  generated always as (
    case
      when length(regexp_replace(coalesce(phone,''),'\D','','g')) = 10
        then regexp_replace(coalesce(phone,''),'\D','','g')
      when length(regexp_replace(coalesce(phone,''),'\D','','g')) = 12
       and left(regexp_replace(coalesce(phone,''),'\D','','g'),2) = '91'
        then right(regexp_replace(coalesce(phone,''),'\D','','g'),10)
      else null
    end
  ) stored;

create unique index if not exists profiles_customer_email_hard_unique
  on public.profiles (lower(trim(email)))
  where role = 'CUSTOMER'
    and email is not null
    and trim(email) <> '';

create unique index if not exists profiles_customer_phone_hard_unique
  on public.profiles (customer_phone_key)
  where role = 'CUSTOMER'
    and customer_phone_key is not null;

-- Backend pre-check used before sending a customer OTP.
create or replace function public.check_customer_signup(
  p_email text,
  p_phone text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_email text := lower(trim(coalesce(p_email,'')));
  v_digits text := regexp_replace(coalesce(p_phone,''),'\D','','g');
  v_phone text;
begin
  if length(v_digits)=10 then
    v_phone := v_digits;
  elsif length(v_digits)=12 and left(v_digits,2)='91' then
    v_phone := right(v_digits,10);
  else
    return jsonb_build_object('allowed',false,'reason','INVALID_INPUT');
  end if;

  if v_email = '' or position('@' in v_email) < 2 then
    return jsonb_build_object('allowed',false,'reason','INVALID_INPUT');
  end if;

  if exists (
    select 1 from public.profiles
    where role='CUSTOMER'
      and lower(trim(coalesce(email,'')))=v_email
  ) then
    return jsonb_build_object('allowed',false,'reason','EMAIL_EXISTS');
  end if;

  if exists (
    select 1 from public.profiles
    where role='CUSTOMER'
      and customer_phone_key=v_phone
  ) then
    return jsonb_build_object('allowed',false,'reason','PHONE_EXISTS');
  end if;

  -- Auth itself is the authoritative email identity store.
  if exists (
    select 1 from auth.users
    where lower(coalesce(email,''))=v_email
  ) then
    return jsonb_build_object('allowed',false,'reason','EMAIL_EXISTS');
  end if;

  return jsonb_build_object('allowed',true);
end;
$$;

revoke all on function public.check_customer_signup(text,text) from public;
grant execute on function public.check_customer_signup(text,text) to anon, authenticated;

-- Final database-boundary profile creation/update.
-- Even if someone bypasses the website, these checks prevent a duplicate
-- customer email or mobile number from being stored.
create or replace function public.ensure_my_profile(
  p_role text,
  p_name text,
  p_phone text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  uid uuid := auth.uid();
  v_email text;
  v_digits text := regexp_replace(coalesce(p_phone,''),'\D','','g');
  v_phone text;
  result jsonb;
begin
  if uid is null then
    raise exception 'Not authenticated';
  end if;

  if p_role not in ('CUSTOMER','DRIVER') then
    raise exception 'Invalid role';
  end if;

  if length(v_digits)=10 then
    v_phone := '+91' || v_digits;
  elsif length(v_digits)=12 and left(v_digits,2)='91' then
    v_phone := '+' || v_digits;
  else
    raise exception 'Invalid Indian mobile number';
  end if;

  select lower(trim(email)) into v_email
  from auth.users
  where id=uid;

  if coalesce(v_email,'')='' then
    raise exception 'Authenticated email is missing';
  end if;

  if p_role='CUSTOMER' then
    if exists (
      select 1 from public.profiles
      where role='CUSTOMER'
        and id<>uid
        and lower(trim(coalesce(email,'')))=v_email
    ) then
      raise exception 'This Gmail is already registered as a customer account';
    end if;

    if exists (
      select 1 from public.profiles
      where role='CUSTOMER'
        and id<>uid
        and customer_phone_key=right(v_phone,10)
    ) then
      raise exception 'This mobile number is already registered as a customer account';
    end if;
  end if;

  insert into public.profiles(id,role,full_name,phone,email,updated_at)
  values(uid,p_role,coalesce(trim(p_name),''),v_phone,v_email,now())
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

revoke all on function public.ensure_my_profile(text,text,text) from public;
grant execute on function public.ensure_my_profile(text,text,text) to authenticated;
