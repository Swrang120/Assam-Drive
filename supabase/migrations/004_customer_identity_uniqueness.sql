-- Assam Drive: backend identity uniqueness
-- Apply this migration to the SAME Supabase project used by the app.
-- Email uniqueness is enforced by Supabase Auth (auth.users.email).
-- Mobile uniqueness is enforced here at the database/trigger level so it
-- cannot be bypassed by the frontend.

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

-- A mobile number must belong to only one account.
-- Empty phones are excluded so incomplete legacy rows do not collide.
create unique index if not exists profiles_mobile_unique_idx
on public.profiles (public.normalize_mobile(phone))
where public.normalize_mobile(phone) <> '';

-- Reject duplicate mobile numbers before an auth user can be created/updated.
-- The signup page stores the number in user metadata as mobile_number.
create or replace function public.prevent_duplicate_mobile_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  new_phone text;
  existing_id uuid;
begin
  new_phone := public.normalize_mobile(coalesce(new.raw_user_meta_data->>'mobile_number',''));

  if new_phone = '' then
    return new;
  end if;

  select p.id
    into existing_id
  from public.profiles p
  where public.normalize_mobile(p.phone) = new_phone
    and p.id <> new.id
  limit 1;

  if existing_id is not null then
    raise exception 'This mobile number is already registered. Please log in instead.'
      using errcode = '23505';
  end if;

  return new;
end;
$$;

drop trigger if exists prevent_duplicate_mobile_auth_user
on auth.users;

create trigger prevent_duplicate_mobile_auth_user
before insert or update of raw_user_meta_data
on auth.users
for each row
execute function public.prevent_duplicate_mobile_auth_user();

-- Harden the profile RPC too. This covers clients that create/sync profiles
-- directly after authentication and keeps the rule enforced server-side.
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

  if clean_phone <> '' then
    select p.id
      into existing_id
    from public.profiles p
    where public.normalize_mobile(p.phone) = clean_phone
      and p.id <> uid
    limit 1;

    if existing_id is not null then
      raise exception 'This mobile number is already registered. Please log in instead.'
        using errcode = '23505';
    end if;
  end if;

  insert into profiles(id,role,full_name,phone,updated_at)
  values(uid,p_role,coalesce(p_name,''),coalesce(p_phone,''),now())
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

-- Do not expose the helper functions to anonymous callers.
revoke all on function public.normalize_mobile(text) from public;
revoke all on function public.prevent_duplicate_mobile_auth_user() from public;
