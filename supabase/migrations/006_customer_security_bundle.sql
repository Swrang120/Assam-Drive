-- Assam Drive: one-click Customer security bundle
-- Run this single file in the SQL Editor of the SAME Supabase project
-- used by Assam Drive (fvigmtojeywwyhfgyeww.supabase.co).

alter table public.profiles add column if not exists email text;

create or replace function public.normalize_mobile(p_phone text)
returns text language sql immutable as $$
  select case when p_phone is null then ''
    else right(regexp_replace(p_phone,'[^0-9]','','g'),10)
  end
$$;

create unique index if not exists profiles_customer_email_unique_secure
on public.profiles(lower(email))
where role='CUSTOMER' and email is not null and email<>'';

create unique index if not exists profiles_customer_mobile_unique_secure
on public.profiles(public.normalize_mobile(phone))
where role='CUSTOMER' and public.normalize_mobile(phone)<>'';

create or replace function public.check_customer_signup(p_email text,p_phone text)
returns jsonb
language plpgsql security definer set search_path=public
as $$
declare e text:=lower(trim(coalesce(p_email,''))); ph text:=public.normalize_mobile(p_phone);
begin
  if e='' or length(ph)<>10 then
    return jsonb_build_object('allowed',false,'reason','INVALID_INPUT');
  end if;
  if exists(select 1 from auth.users where lower(coalesce(email,''))=e)
     or exists(select 1 from profiles where role='CUSTOMER' and lower(coalesce(email,''))=e)
  then return jsonb_build_object('allowed',false,'reason','EMAIL_EXISTS'); end if;
  if exists(select 1 from profiles where role='CUSTOMER' and public.normalize_mobile(phone)=ph)
  then return jsonb_build_object('allowed',false,'reason','PHONE_EXISTS'); end if;
  return jsonb_build_object('allowed',true);
end $$;

revoke all on function public.check_customer_signup(text,text) from public;
grant execute on function public.check_customer_signup(text,text) to anon,authenticated;

create or replace function public.prevent_duplicate_customer_mobile()
returns trigger
language plpgsql security definer set search_path=public
as $$
declare ph text:=public.normalize_mobile(coalesce(new.raw_user_meta_data->>'mobile_number',''));
begin
  if upper(coalesce(new.raw_user_meta_data->>'requested_role',''))='CUSTOMER' then
    if length(ph)<>10 then raise exception 'Customer mobile number must contain exactly 10 digits.'; end if;
    if exists(select 1 from profiles where role='CUSTOMER' and public.normalize_mobile(phone)=ph and id<>new.id)
    then raise exception 'This mobile number is already registered. Please log in instead.' using errcode='23505'; end if;
  end if;
  return new;
end $$;

drop trigger if exists prevent_duplicate_mobile_auth_user on auth.users;
create trigger prevent_duplicate_mobile_auth_user
before insert or update of raw_user_meta_data on auth.users
for each row execute function public.prevent_duplicate_customer_mobile();

create or replace function public.ensure_my_profile(p_role text,p_name text,p_phone text)
returns jsonb
language plpgsql security definer set search_path=public
as $$
declare uid uuid:=auth.uid(); existing_role text; ph text:=public.normalize_mobile(p_phone); e text; result jsonb;
begin
  if uid is null then raise exception 'Not authenticated'; end if;
  if p_role not in('CUSTOMER','DRIVER') then raise exception 'Invalid role'; end if;

  select role into existing_role from profiles where id=uid;
  if existing_role is not null and existing_role<>p_role then
    raise exception 'This account is registered as %; please use the correct login.',existing_role;
  end if;

  select lower(email) into e from auth.users where id=uid;

  if p_role='CUSTOMER' then
    if length(ph)<>10 then raise exception 'Customer mobile number must contain exactly 10 digits.'; end if;
    if exists(select 1 from profiles where role='CUSTOMER' and id<>uid and lower(coalesce(email,''))=coalesce(e,'') and coalesce(e,'')<>'')
    then raise exception 'This Gmail is already registered as a customer account'; end if;
    if exists(select 1 from profiles where role='CUSTOMER' and id<>uid and public.normalize_mobile(phone)=ph)
    then raise exception 'This mobile number is already registered as a customer account'; end if;
  end if;

  insert into profiles(id,role,full_name,phone,email,updated_at)
  values(uid,p_role,coalesce(p_name,''),ph,e,now())
  on conflict(id) do update set full_name=excluded.full_name,phone=excluded.phone,email=excluded.email,updated_at=now();

  if p_role='DRIVER' then
    insert into driver_profiles(id,vehicle_type,updated_at) values(uid,'BIKE',now()) on conflict(id) do nothing;
  end if;

  select jsonb_build_object('id',p.id,'role',p.role,'full_name',p.full_name,'phone',p.phone,'email',p.email,
    'driver',case when p.role='DRIVER' then (select to_jsonb(d) from driver_profiles d where d.id=p.id) else null end)
  into result from profiles p where p.id=uid;
  return result;
end $$;

create or replace function public.get_my_account_role()
returns jsonb
language plpgsql security definer set search_path=public
as $$
declare uid uuid:=auth.uid(); result jsonb;
begin
  if uid is null then raise exception 'Not authenticated'; end if;
  select jsonb_build_object('id',p.id,'role',p.role,'full_name',p.full_name,'phone',p.phone,'email',p.email)
  into result from profiles p where p.id=uid;
  if result is null then raise exception 'Account profile not found'; end if;
  return result;
end $$;

revoke all on function public.get_my_account_role() from public;
grant execute on function public.get_my_account_role() to authenticated;