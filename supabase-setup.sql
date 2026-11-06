-- Safe to re-run in Supabase SQL Editor. Existing catalog and customer data is preserved.
-- Expected existing tables: profiles(id, display_name, role), products(id, name,
-- category, price, stock, description, image, active), orders(id, user_id,
-- customer_name, phone, address, items, total, status, created_at).

create extension if not exists pgcrypto;

alter table public.profiles add column if not exists preferred_language text not null default 'ar';
alter table public.profiles drop constraint if exists profiles_preferred_language_check;
alter table public.profiles add constraint profiles_preferred_language_check check (preferred_language in ('ar','en'));

alter table public.products
  add column if not exists discount_percent numeric(5,2) not null default 0,
  add column if not exists coupon text,
  add column if not exists rating numeric(2,1) not null default 0,
  add column if not exists reviews integer not null default 0;
alter table public.products drop constraint if exists products_discount_percent_check;
alter table public.products add constraint products_discount_percent_check check (discount_percent between 0 and 100);
alter table public.products drop constraint if exists products_rating_check;
alter table public.products add constraint products_rating_check check (rating between 0 and 5);
alter table public.products drop constraint if exists products_reviews_check;
alter table public.products add constraint products_reviews_check check (reviews >= 0);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, display_name, role)
  values (new.id, coalesce(nullif(new.raw_user_meta_data ->> 'full_name',''), nullif(new.raw_user_meta_data ->> 'name',''), ''), 'customer')
  on conflict (id) do nothing;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.protect_profile_role()
returns trigger language plpgsql set search_path = '' as $$
begin
  if old.role is distinct from new.role and auth.uid() is not null then
    raise exception 'Only a trusted administrator can change account roles';
  end if;
  return new;
end;
$$;
drop trigger if exists protect_profile_role on public.profiles;
create trigger protect_profile_role before update on public.profiles
for each row execute procedure public.protect_profile_role();

create or replace function public.is_store_owner()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles where id = (select auth.uid()) and role = 'owner');
$$;
revoke all on function public.is_store_owner() from public;
grant execute on function public.is_store_owner() to anon, authenticated;

create table if not exists public.user_carts (
  user_id uuid primary key references auth.users(id) on delete cascade,
  items jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
create table if not exists public.user_favorites (
  user_id uuid not null references auth.users(id) on delete cascade,
  product_id uuid not null references public.products(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, product_id)
);
create table if not exists public.user_addresses (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  recipient text not null, phone text not null, address text not null,
  created_at timestamptz not null default now()
);
create index if not exists user_addresses_user_created_idx on public.user_addresses(user_id, created_at desc);
create index if not exists orders_user_created_idx on public.orders(user_id, created_at desc);

alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.user_carts enable row level security;
alter table public.user_favorites enable row level security;
alter table public.user_addresses enable row level security;

-- Remove existing policies on managed tables first so this script can be re-run.
do $$
declare p record;
begin
  for p in select schemaname, tablename, policyname from pg_policies
    where schemaname = 'public'
      and tablename in ('profiles','products','orders','user_carts','user_favorites','user_addresses')
  loop
    execute format('drop policy %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end;
$$;

create policy "profile owner or self reads" on public.profiles for select to authenticated
  using ((select auth.uid()) = id or (select public.is_store_owner()));
create policy "self updates profile" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
create policy "active catalog is public" on public.products for select to anon, authenticated
  using (active or (select public.is_store_owner()));
create policy "store owner manages catalog" on public.products for all to authenticated
  using ((select public.is_store_owner())) with check ((select public.is_store_owner()));
create policy "self or owner reads orders" on public.orders for select to authenticated
  using ((select auth.uid()) = user_id or (select public.is_store_owner()));
create policy "customer creates own order" on public.orders for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy "account owns cart" on public.user_carts for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "account owns favorites" on public.user_favorites for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "account owns addresses" on public.user_addresses for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

grant select, update on public.profiles to authenticated;
grant select on public.products to anon, authenticated;
grant insert, update, delete on public.products to authenticated;
grant select, insert on public.orders to authenticated;
grant select, insert, update, delete on public.user_carts, public.user_favorites, public.user_addresses to authenticated;

insert into storage.buckets (id, name, public)
values ('product-images', 'product-images', true)
on conflict (id) do update set public = true;
drop policy if exists "product images are public" on storage.objects;
create policy "product images are public" on storage.objects for select to anon, authenticated
  using (bucket_id = 'product-images');
drop policy if exists "store owner uploads product images" on storage.objects;
create policy "store owner uploads product images" on storage.objects for insert to authenticated
  with check (bucket_id = 'product-images' and (select public.is_store_owner()));
drop policy if exists "store owner updates product images" on storage.objects;
create policy "store owner updates product images" on storage.objects for update to authenticated
  using (bucket_id = 'product-images' and (select public.is_store_owner()))
  with check (bucket_id = 'product-images' and (select public.is_store_owner()));
drop policy if exists "store owner deletes product images" on storage.objects;
create policy "store owner deletes product images" on storage.objects for delete to authenticated
  using (bucket_id = 'product-images' and (select public.is_store_owner()));

-- Add starter catalog only when no products exist yet.
insert into public.products (id, name, category, price, stock, description, image, active, created_at)
select gen_random_uuid(), s.name, s.category, s.price, s.stock, s.description, s.image, true, now()
from (values
  ('سماعة لاسلكية بعزل صوت وميكروفون','إكسسوارات الكمبيوتر',1249,12,'سماعة لاسلكية مريحة مع ميكروفون للاستخدام اليومي.','https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=600&q=80'),
  ('كيبورد ميكانيكي بإضاءة RGB','إكسسوارات الكمبيوتر',899,8,'كيبورد عملي بإضاءة ملونة وتجربة كتابة مريحة.','https://images.unsplash.com/photo-1587829741301-dc798b83add3?auto=format&fit=crop&w=600&q=80'),
  ('شاحن سريع متعدد المنافذ 65 واط','الشواحن والأدابتورات',649,18,'شاحن سريع متعدد المنافذ للأجهزة المتوافقة.','https://images.unsplash.com/photo-1583863788434-e58a36330cf0?auto=format&fit=crop&w=600&q=80'),
  ('وحدة تخزين SSD خارجية 1 تيرابايت','وحدات التخزين',2199,6,'وحدة تخزين خارجية سريعة لحفظ ملفاتك.','https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?auto=format&fit=crop&w=600&q=80'),
  ('ماوس لاسلكي مريح','إكسسوارات الكمبيوتر',389,20,'ماوس لاسلكي للاستخدام المكتبي واليومي.','https://images.unsplash.com/photo-1527814050087-3793815479db?auto=format&fit=crop&w=600&q=80'),
  ('كابل USB-C سريع بطول مترين','الكابلات والتوصيلات',199,30,'كابل USB-C للشحن ونقل البيانات.','https://images.unsplash.com/photo-1558618666-fcd25c85cd64?auto=format&fit=crop&w=600&q=80'),
  ('سماعة بلوتوث محمولة','إلكترونيات متنوعة',749,9,'سماعة محمولة للاستماع في المنزل وخارجه.','https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?auto=format&fit=crop&w=600&q=80'),
  ('كاميرا ويب عالية الدقة','قطع غيار الكمبيوتر',1099,5,'كاميرا ويب للاجتماعات ومكالمات الفيديو.','https://images.unsplash.com/photo-1587826080692-f439cd0b70da?auto=format&fit=crop&w=600&q=80')
) as s(name, category, price, stock, description, image)
where not exists (select 1 from public.products);

-- Set the store owner from the trusted SQL Editor after confirming the account email:
-- update public.profiles p set role = 'owner' from auth.users u
-- where p.id = u.id and lower(u.email) = lower('YOUR-EMAIL@example.com');
