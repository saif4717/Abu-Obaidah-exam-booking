-- نظام حجز الاختبارات القصيرة | Supabase PostgreSQL
-- شغّل هذا الملف مرة واحدة في SQL Editor داخل مشروع Supabase.

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

alter table public.bookings enable row level security;
alter table public.exam_admins enable row level security;

-- جدول المواعيد للقراءة العامة حتى يتمكن المعلمون من رؤية التوفر.
drop policy if exists "Anyone can view bookings" on public.bookings;
create policy "Anyone can view bookings" on public.bookings
  for select to anon, authenticated using (true);

-- الحجز متاح للمعلمين بدون تسجيل دخول؛ لا يوجد إذن عام للتعديل أو الحذف.
drop policy if exists "Anyone can create a booking" on public.bookings;
create policy "Anyone can create a booking" on public.bookings
  for insert to anon, authenticated with check (
    char_length(trim(teacher_name)) between 2 and 80
    and extract(isodow from exam_date) not in (5, 6)
  );

-- لا يستطيع المستخدمون قراءة سوى سجل صلاحيتهم الإدارية.
drop policy if exists "Admins can read their own role" on public.exam_admins;
create policy "Admins can read their own role" on public.exam_admins
  for select to authenticated using (auth.uid() = user_id);

create or replace function public.is_exam_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from public.exam_admins where user_id = auth.uid());
$$;
revoke all on function public.is_exam_admin() from public;
grant execute on function public.is_exam_admin() to authenticated;

-- الإلغاء يمر عبر دالة تتحقق من دور الإدارة على الخادم.
create or replace function public.cancel_booking(booking_id uuid)
returns void
language plpgsql
security definer
set search_path = public
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

grant select, insert on public.bookings to anon, authenticated;
grant select on public.exam_admins to authenticated;

-- تُفعّل التنبيهات الفورية إذا لم تكن مفعّلة على المشروع بالفعل.
do $$ begin
  alter publication supabase_realtime add table public.bookings;
exception when duplicate_object then null;
when undefined_object then null;
end $$;
