-- Assam Drive: customer identity uniqueness
-- Email uniqueness is enforced by Supabase Auth (auth.users).
-- Customer mobile uniqueness is enforced in PostgreSQL so the rule cannot
-- be bypassed by the frontend.

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

-- Refuse migration if existing Customer rows already contain duplicate mobiles.
do $$
declare duplicate_count integer;
begin
  select count(*) into duplicate_count
  from (
    select public.normalize_mobile(phone) as phone_key
    from public.profiles
    where role='CUSTOMER'
      and public.normalize_mobile(phone) <> ''
    group by public.normalize_mobile(phone)
    having count(*) > 1
  ) duplicates;

  if duplicate_count > 0 then
    raise exception 'Duplicate customer mobile numbers already exist. Resolve them before enabling the unique customer-mobile rule.';
  end if;
end $$;

-- One mobile number = one Customer account.
-- Driver numbers are not included in this Customer-only rule yet.
drop index if exists public.profiles_mobile_unique_idx;
create unique index if not exists profiles_customer_mobile_unique_idx
on public.profiles (public.normalize_mobile(phone))
where role='CUSTOMER' and public.normalize_mobile(phone) <> '';

-- Block a second Auth account when the signup metadata contains a mobile
-- already owned by another Customer profile.
create or replace function public.prevent_duplicate_customer_mobile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  new_phone text;
  existing_id uuid;
  requested_role text;
begin
  requested_role := upper(coalesce(new.raw_user_meta_data->>'requested_role',''));

  if requested_role <> 'CUSTOMER' then
    return new;
  end if;

  new_phone := public.normalize_mobile(coalesce(new.raw_user_meta_data->>'mobile_number',''));

  if new_phone = '' then
    raise exception 'Customer mobile number is required.'
      using errcode='P0001';
  end if;

  if length(new_phone) <> 10 then
    raise exception 'Customer mobile number must contain exactly 10 digits.'
      using errcode='P0001';
  end if;

  select p.id into existing_id
  from public.profiles p
  where p.role='CUSTOMER'
    and public.normalize_mobile(p.phone)=new_phone
    and p.id<>new.id
  limit 1;

  if existing_id is not null then
    raise exception 'This mobile number is already registered. Please log in instead.'
      using errcode='23505';
  end if;

  return new;
end;
$$;

drop trigger if exists prevent_duplicate_mobile_auth_user on auth.users;
create trigger prevent_duplicate_mobile_auth_user
before insert or update of raw_user_meta_data on auth.users
for each row execute function public.prevent_duplicate_customer_mobile();

-- Harden profile creation/sync as well. The unique index remains the final
-- race-safe database constraint.
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
  result jsonb;
  existing_id uuid;
begin
  if uid is null then
    raise exception 'Not authenticated';
  end if;

  if p_role not in ('CUSTOMER','DRIVER') then
    raise exception 'Invalid role';
  end if;

  if p_role='CUSTOMER' then
    if clean_phone='' or length(clean_phone)<>10 then
      raise exception 'Customer mobile number must contain exactly 10 digits.';
    end if;

    select p.id into existing_id
    from public.profiles p
    where p.role='CUSTOMER'
      and public.normalize_mobile(p.phone)=clean_phone
      and p.id<>uid
    limit 1;

    if existing_id is not null then
      raise exception 'This mobile number is already registered. Please log in instead.'
        using errcode='23505';
    end if;
  end if;

  insert into profiles(id,role,full_name,phone,updated_at)
  values(uid,p_role,coalesce(p_name,''),clean_phone,now())
  on conflict(id) do update
    set role=excluded.role,
        full_name=excluded.full_name,
        phone=excluded.phone,
        updated_at=now();

  if p_role='DRIVER' then
    insert into driver_profiles(id,vehicle_type,updated_at)
    values(uid,'BIKE',now())
    on conflict(id) do nothing;
  end if;

  select jsonb_build_object(
    'id',p.id,
    'role',p.role,
    'full_name',p.full_name,
    'phone',p.phone,
    'driver',
      case when p.role='DRIVER'
        then (select to_jsonb(d) from driver_profiles d where d.id=p.id)
        else null
      end
  )
  into result
  from profiles p
  where p.id=uid;

  return result;
end;
$$;

revoke all on function public.normalize_mobile(text) from public;
revoke all on function public.prevent_duplicate_customer_mobile() from public;

commit;