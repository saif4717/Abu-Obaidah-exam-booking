-- نظام حجز الاختبارات القصيرة | Supabase PostgreSQL
-- شغّل هذا الملف في SQL Editor داخل مشروع Supabase بعد نشر الواجهة.
-- يُبقي قراءة التقويم متاحة، ويجعل الحجز عبر دالة تتحقق من الرمز المؤقت.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.bookings (
  id uuid primary key default gen_random_uuid(),
  teacher_name text not null check (char_length(trim(teacher_name)) between 2 and 80),
  class_section text not null check (class_section ~ '^(10/(?:[1-9]|10|11)|11/(?:[1-9]|1[0-2])|12/(?:[1-9]|10|11))$'),
  exam_date date not null check (extract(isodow from exam_date) not in (5, 6)),
  created_at timestamptz not null default now(),
  constraint one_booking_per_class_per_day unique (exam_date, class_section)
);

create table if not exists public.exam_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

-- لا يُتاح الرمز نفسه عبر PostgREST؛ تحفظ قاعدة البيانات hash فقط.
create table if not exists public.booking_access_codes (
  singleton boolean primary key default true check (singleton),
  code_hash text not null,
  expires_at timestamptz not null,
  updated_at timestamptz not null default now()
);

alter table public.bookings enable row level security;
alter table public.exam_admins enable row level security;
alter table public.booking_access_codes enable row level security;

-- بيانات الحجوزات مقروءة للتقويم، لكن الكتابة لا تتم مباشرة عبر anon.
drop policy if exists "Anyone can view bookings" on public.bookings;
create policy "Anyone can view bookings" on public.bookings
  for select to anon, authenticated using (true);

drop policy if exists "Anyone can create a booking" on public.bookings;
revoke all on public.bookings from public, anon, authenticated;
grant select on public.bookings to anon, authenticated;
revoke all on public.booking_access_codes from public, anon, authenticated;

-- لا يستطيع المستخدمون قراءة سوى سجل صلاحيتهم الإدارية.
drop policy if exists "Admins can read their own role" on public.exam_admins;
create policy "Admins can read their own role" on public.exam_admins
  for select to authenticated using (auth.uid() = user_id);
grant select on public.exam_admins to authenticated;

create or replace function public.is_exam_admin()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select exists (select 1 from public.exam_admins where user_id = auth.uid());
$$;
revoke all on function public.is_exam_admin() from public;
grant execute on function public.is_exam_admin() to authenticated;

-- تغيير الرمز متاح لحساب إدارة معتمد فقط. الرمز يُخزّن كـ bcrypt صالحاً 14 يوماً.
create or replace function public.set_booking_access_code(p_new_code text)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_code text := btrim(p_new_code);
begin
  if auth.uid() is null or not exists (
    select 1 from public.exam_admins where user_id = auth.uid()
  ) then
    raise exception 'admin access required' using errcode = '42501';
  end if;
  if v_code is null or v_code !~ '^[A-Za-z0-9]{12,64}$' then
    raise exception 'code must contain 12 to 64 English letters or digits' using errcode = '22023';
  end if;

  insert into public.booking_access_codes (singleton, code_hash, expires_at, updated_at)
  values (true, crypt(v_code, gen_salt('bf', 10)), now() + interval '14 days', now())
  on conflict (singleton) do update
    set code_hash = excluded.code_hash,
        expires_at = excluded.expires_at,
        updated_at = excluded.updated_at;
end;
$$;
revoke all on function public.set_booking_access_code(text) from public, anon;
grant execute on function public.set_booking_access_code(text) to authenticated;

-- حالة صلاحية الرمز لا تظهر إلا لحساب الإدارة.
create or replace function public.get_booking_access_code_status()
returns table(is_active boolean, expires_at timestamptz)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
begin
  if auth.uid() is null or not exists (
    select 1 from public.exam_admins where user_id = auth.uid()
  ) then
    raise exception 'admin access required' using errcode = '42501';
  end if;

  return query
    select coalesce(c.expires_at > now(), false), c.expires_at
    from (select true as singleton) as seed
    left join public.booking_access_codes as c on c.singleton = seed.singleton;
end;
$$;
revoke all on function public.get_booking_access_code_status() from public, anon;
grant execute on function public.get_booking_access_code_status() to authenticated;

-- هذه هي نقطة الحجز الوحيدة للواجهة العامة: الرمز يُفحص داخل قاعدة البيانات.
create or replace function public.create_booking_with_code(
  p_teacher_name text,
  p_class_section text,
  p_exam_date date,
  p_access_code text
)
returns table(id uuid, teacher_name text, class_section text, exam_date date, created_at timestamptz)
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_hash text;
  v_expiry timestamptz;
  v_code text := btrim(p_access_code);
begin
  if char_length(trim(coalesce(p_teacher_name, ''))) not between 2 and 80 then
    raise exception 'invalid teacher name' using errcode = '22023';
  end if;
  if p_class_section !~ '^(10/(?:[1-9]|10|11)|11/(?:[1-9]|1[0-2])|12/(?:[1-9]|10|11))$' then
    raise exception 'invalid class section' using errcode = '22023';
  end if;
  if p_exam_date is null or p_exam_date < current_date then
    raise exception 'exam date must not be in the past' using errcode = '22023';
  end if;
  if v_code is null or v_code !~ '^[A-Za-z0-9]{12,64}$' then
    raise exception 'invalid or expired booking access code' using errcode = 'P0001';
  end if;
  if extract(isodow from p_exam_date) in (5, 6) then
    raise exception 'weekend bookings are not allowed' using errcode = '23514';
  end if;

  select c.code_hash, c.expires_at into v_hash, v_expiry
  from public.booking_access_codes as c
  where c.singleton = true;

  if v_hash is null or v_expiry <= now() or v_code is null or crypt(v_code, v_hash) <> v_hash then
    raise exception 'invalid or expired booking access code' using errcode = 'P0001';
  end if;

  return query
    insert into public.bookings as b (teacher_name, class_section, exam_date)
    values (trim(p_teacher_name), p_class_section, p_exam_date)
    returning b.id, b.teacher_name, b.class_section, b.exam_date, b.created_at;
end;
$$;
revoke all on function public.create_booking_with_code(text, text, date, text) from public;
grant execute on function public.create_booking_with_code(text, text, date, text) to anon, authenticated;

-- الإلغاء يمر عبر دالة تتحقق من دور الإدارة على الخادم.
create or replace function public.cancel_booking(booking_id uuid)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if not exists (select 1 from public.exam_admins where user_id = auth.uid()) then
    raise exception 'admin access required' using errcode = '42501';
  end if;
  delete from public.bookings where id = booking_id;
  if not found then
    raise exception 'booking not found' using errcode = 'P0002';
  end if;
end;
$$;
revoke all on function public.cancel_booking(uuid) from public;
grant execute on function public.cancel_booking(uuid) to authenticated;

-- تُفعّل التنبيهات الفورية إذا لم تكن مفعّلة على المشروع بالفعل.
do $$ begin
  alter publication supabase_realtime add table public.bookings;
exception when duplicate_object then null;
when undefined_object then null;
end $$;
