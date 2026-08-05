-- WTS Central Registry production workflows.
--
-- This migration is additive. It creates pending staff registrations,
-- academic context, and historical staff allocations without inventing
-- identities, staff, students, assignments, permissions, or credentials.
-- All browser writes go through session-bound security-definer functions.

alter table public.staff_attendance_profiles
  add column if not exists school_section text;

comment on column public.staff_attendance_profiles.school_section is
  'School section assigned by Central Registry management.';

create table if not exists public.school_staff_registrations (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  email text,
  phone text,
  whatsapp_number text,
  address text,
  emergency_contact text,
  photo_data text,
  registration_status text not null default 'pending'
    check (registration_status in ('pending','under_review','approved','rejected','withdrawn')),
  request_fingerprint text not null,
  submitted_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by_person_id uuid references public.school_people(id),
  rejection_reason text,
  approved_staff_id uuid references public.staff_attendance_profiles(id),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (length(trim(full_name)) between 2 and 160),
  check (email is null or length(trim(email)) between 3 and 254),
  check (phone is null or length(trim(phone)) between 3 and 40),
  check (whatsapp_number is null or length(trim(whatsapp_number)) between 3 and 40),
  check (address is null or length(trim(address)) <= 500),
  check (emergency_contact is null or length(trim(emergency_contact)) <= 240),
  check (photo_data is null or length(photo_data) <= 260000)
);

create index if not exists school_staff_registrations_status_idx
  on public.school_staff_registrations (registration_status, submitted_at desc);
create index if not exists school_staff_registrations_email_idx
  on public.school_staff_registrations (lower(email)) where email is not null;
create index if not exists school_staff_registrations_phone_idx
  on public.school_staff_registrations (phone) where phone is not null;

alter table public.school_staff_registrations enable row level security;
revoke all on table public.school_staff_registrations from public, anon, authenticated;

create table if not exists public.school_academic_sessions (
  session_name text primary key,
  display_name text not null,
  session_status text not null default 'active'
    check (session_status in ('active','archived')),
  starts_on date,
  ends_on date,
  created_by_person_id uuid references public.school_people(id),
  updated_by_person_id uuid references public.school_people(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (length(trim(session_name)) between 3 and 80),
  check (ends_on is null or starts_on is null or ends_on >= starts_on)
);

create table if not exists public.school_academic_terms (
  id uuid primary key default gen_random_uuid(),
  academic_session text not null references public.school_academic_sessions(session_name),
  term_name text not null check (term_name in ('1st Term','2nd Term','3rd Term')),
  term_status text not null default 'open'
    check (term_status in ('open','closed','archived')),
  is_current boolean not null default false,
  starts_on date,
  ends_on date,
  closed_at timestamptz,
  last_reopened_at timestamptz,
  last_reopened_by_person_id uuid references public.school_people(id),
  last_reopen_reason text,
  last_reopen_approval text,
  metadata jsonb not null default '{}'::jsonb,
  created_by_person_id uuid references public.school_people(id),
  updated_by_person_id uuid references public.school_people(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (academic_session, term_name),
  check (ends_on is null or starts_on is null or ends_on >= starts_on),
  check (not is_current or term_status = 'open')
);

create unique index if not exists school_academic_terms_one_current_idx
  on public.school_academic_terms (is_current) where is_current;
create index if not exists school_academic_terms_context_idx
  on public.school_academic_terms (academic_session, term_status, starts_on);

alter table public.school_academic_sessions enable row level security;
alter table public.school_academic_terms enable row level security;
revoke all on table public.school_academic_sessions, public.school_academic_terms
  from public, anon, authenticated;

-- Backfill only the already-authoritative settings values. This does not add
-- a new school session or term; it gives management a historical calendar row
-- for the current production context.
insert into public.school_academic_sessions(session_name, display_name)
select trim(s.value), trim(s.value)
from public.settings s
where s.key = 'session' and nullif(trim(s.value), '') is not null
on conflict (session_name) do nothing;

insert into public.school_academic_terms(academic_session, term_name, term_status, is_current)
select trim(s.value), trim(t.value), 'open', true
from public.settings s
join public.settings t on t.key = 'term'
where s.key = 'session'
  and nullif(trim(s.value), '') is not null
  and trim(t.value) in ('1st Term','2nd Term','3rd Term')
on conflict (academic_session, term_name) do nothing;

create table if not exists public.school_staff_class_allocations (
  id uuid primary key default gen_random_uuid(),
  staff_id uuid not null references public.staff_attendance_profiles(id),
  person_id uuid not null references public.school_people(id),
  academic_session text not null,
  term_name text not null,
  class_key text not null references public.school_classes(class_key),
  responsibility text not null check (responsibility in ('class_teacher','assistant_class_teacher')),
  allocation_status text not null default 'active'
    check (allocation_status in ('active','ended','revoked')),
  effective_from timestamptz not null default now(),
  effective_until timestamptz,
  assigned_by_person_id uuid references public.school_people(id),
  assigned_at timestamptz not null default now(),
  revoked_by_person_id uuid references public.school_people(id),
  revoked_at timestamptz,
  revocation_reason text,
  reason text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (academic_session, term_name)
    references public.school_academic_terms(academic_session, term_name),
  check (effective_until is null or effective_until > effective_from)
);

create table if not exists public.school_staff_subject_allocations (
  id uuid primary key default gen_random_uuid(),
  staff_id uuid not null references public.staff_attendance_profiles(id),
  person_id uuid not null references public.school_people(id),
  academic_session text not null,
  term_name text not null,
  class_key text not null,
  subject_index integer not null,
  allocation_status text not null default 'active',
  effective_from timestamptz not null default now(),
  effective_until timestamptz,
  assigned_by_person_id uuid references public.school_people(id),
  assigned_at timestamptz not null default now(),
  revoked_by_person_id uuid references public.school_people(id),
  revoked_at timestamptz,
  revocation_reason text,
  reason text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (academic_session, term_name)
    references public.school_academic_terms(academic_session, term_name),
  foreign key (class_key, subject_index)
    references public.result_subject_catalog(class_key, subject_index),
  check (effective_until is null or effective_until > effective_from)
);

create unique index if not exists school_class_allocations_one_main_teacher_idx
  on public.school_staff_class_allocations (academic_session, term_name, class_key)
  where responsibility = 'class_teacher' and allocation_status = 'active';
create unique index if not exists school_class_allocations_one_staff_context_idx
  on public.school_staff_class_allocations (staff_id, academic_session, term_name, class_key, responsibility)
  where allocation_status = 'active';
create unique index if not exists school_subject_allocations_one_staff_context_idx
  on public.school_staff_subject_allocations (staff_id, academic_session, term_name, class_key, subject_index)
  where allocation_status = 'active';
create index if not exists school_class_allocations_context_idx
  on public.school_staff_class_allocations (academic_session, term_name, class_key, allocation_status);
create index if not exists school_subject_allocations_context_idx
  on public.school_staff_subject_allocations (academic_session, term_name, class_key, subject_index, allocation_status);
create index if not exists school_staff_class_allocations_staff_idx
  on public.school_staff_class_allocations (staff_id, created_at desc);
create index if not exists school_staff_subject_allocations_staff_idx
  on public.school_staff_subject_allocations (staff_id, created_at desc);

alter table public.school_staff_class_allocations enable row level security;
alter table public.school_staff_subject_allocations enable row level security;
revoke all on table public.school_staff_class_allocations, public.school_staff_subject_allocations
  from public, anon, authenticated;

create or replace function public.school_academic_current()
returns jsonb
language sql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
  select jsonb_build_object(
    'academic_session', coalesce((select academic_session from public.school_academic_terms where is_current order by updated_at desc limit 1), (select value from public.settings where key = 'session')),
    'term', coalesce((select term_name from public.school_academic_terms where is_current order by updated_at desc limit 1), (select value from public.settings where key = 'term')),
    'term_status', coalesce((select term_status from public.school_academic_terms where is_current order by updated_at desc limit 1), 'open'),
    'term_id', (select id from public.school_academic_terms where is_current order by updated_at desc limit 1)
  );
$function$;

revoke all on function public.school_academic_current() from public, anon, authenticated;

create or replace function public.school_academic_term_write_gate(
  p_academic_session text,
  p_term text
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_term public.school_academic_terms%rowtype;
begin
  select * into v_term
  from public.school_academic_terms
  where academic_session = trim(coalesce(p_academic_session, ''))
    and term_name = trim(coalesce(p_term, ''));
  if not found then
    return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TERM_NOT_FOUND');
  end if;
  if v_term.term_status <> 'open' then
    return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TERM_READ_ONLY', 'term_status', v_term.term_status);
  end if;
  return jsonb_build_object('ok', true, 'academic_session', v_term.academic_session, 'term', v_term.term_name);
end;
$function$;

revoke all on function public.school_academic_term_write_gate(text, text)
  from public, anon, authenticated;

create or replace function public.school_staff_public_registration_submit(p_payload jsonb)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_name text := nullif(trim(coalesce(p_payload ->> 'fullName', '')), '');
  v_email text := lower(nullif(trim(coalesce(p_payload ->> 'email', '')), ''));
  v_phone text := nullif(trim(coalesce(p_payload ->> 'phone', '')), '');
  v_whatsapp text := nullif(trim(coalesce(p_payload ->> 'whatsappNumber', '')), '');
  v_address text := nullif(trim(coalesce(p_payload ->> 'address', '')), '');
  v_emergency text := nullif(trim(coalesce(p_payload ->> 'emergencyContact', '')), '');
  v_photo text := nullif(trim(coalesce(p_payload ->> 'photo', '')), '');
  v_fingerprint text;
begin
  if v_name is null or length(v_name) < 2 or length(v_name) > 160 then
    return jsonb_build_object('ok', false, 'code', 'FULL_NAME_REQUIRED');
  end if;
  if v_email is null or length(v_email) > 254 or v_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' then
    return jsonb_build_object('ok', false, 'code', 'VALID_EMAIL_REQUIRED');
  end if;
  if v_phone is null or length(v_phone) < 3 or length(v_phone) > 40 then
    return jsonb_build_object('ok', false, 'code', 'PHONE_REQUIRED');
  end if;
  if v_whatsapp is not null and length(v_whatsapp) > 40 then
    return jsonb_build_object('ok', false, 'code', 'WHATSAPP_NUMBER_INVALID');
  end if;
  if v_photo is not null and (length(v_photo) > 260000 or v_photo !~ '^data:image/[a-zA-Z0-9.+-]+;base64,') then
    return jsonb_build_object('ok', false, 'code', 'PHOTOGRAPH_INVALID');
  end if;
  v_fingerprint := md5(lower(v_name) || '|' || coalesce(v_email, '') || '|' || coalesce(v_phone, '') || '|' || coalesce(v_whatsapp, ''));

  if exists (
    select 1 from public.staff_attendance_profiles s
    where s.registration_status in ('active','pending','suspended')
      and (lower(coalesce(s.email, '')) = v_email or s.phone = v_phone or s.whatsapp_number = v_whatsapp)
  ) or exists (
    select 1 from public.school_staff_registrations r
    where r.registration_status in ('pending','under_review','approved')
      and (lower(coalesce(r.email, '')) = v_email or r.phone = v_phone or r.whatsapp_number = v_whatsapp)
  ) then
    return jsonb_build_object('ok', true, 'code', 'STAFF_REGISTRATION_ALREADY_ON_FILE');
  end if;

  insert into public.school_staff_registrations(
    full_name, email, phone, whatsapp_number, address, emergency_contact,
    photo_data, registration_status, request_fingerprint
  ) values (
    v_name, v_email, v_phone, v_whatsapp, v_address, v_emergency,
    v_photo, 'pending', v_fingerprint
  );
  return jsonb_build_object('ok', true, 'code', 'STAFF_REGISTRATION_SUBMITTED');
end;
$function$;

revoke all on function public.school_staff_public_registration_submit(jsonb)
  from public, authenticated;
grant execute on function public.school_staff_public_registration_submit(jsonb) to anon;


create or replace function public.school_academic_calendar_management_session_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_actor_person_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_action text := lower(trim(coalesce(p_action, '')));
  v_session_name text;
  v_display_name text;
  v_term_name text;
  v_reason text;
  v_approval text;
  v_status text;
  v_starts date;
  v_ends date;
  v_term_id uuid;
  v_before jsonb;
  v_after jsonb;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;
  v_actor_person_id := wts_internal.central_management_actor(v_session);
  if v_actor_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED');
  end if;

  if v_action = 'read' then
    return jsonb_build_object(
      'ok', true,
      'current', public.school_academic_current(),
      'sessions', coalesce((
        select jsonb_agg(jsonb_build_object(
          'session_name', s.session_name, 'display_name', s.display_name,
          'session_status', s.session_status, 'starts_on', s.starts_on,
          'ends_on', s.ends_on
        ) order by s.session_name desc)
        from public.school_academic_sessions s
      ), '[]'::jsonb),
      'terms', coalesce((
        select jsonb_agg(jsonb_build_object(
          'id', t.id, 'academic_session', t.academic_session,
          'term_name', t.term_name, 'term_status', t.term_status,
          'is_current', t.is_current, 'starts_on', t.starts_on,
          'ends_on', t.ends_on, 'closed_at', t.closed_at,
          'last_reopened_at', t.last_reopened_at,
          'last_reopen_reason', t.last_reopen_reason,
          'last_reopen_approval', t.last_reopen_approval
        ) order by t.academic_session desc, t.term_name)
        from public.school_academic_terms t
      ), '[]'::jsonb),
      'settings', jsonb_build_object(
        'session', (select value from public.settings where key = 'session'),
        'term', (select value from public.settings where key = 'term')
      )
    );
  end if;

  if v_action = 'createsession' then
    v_session_name := nullif(trim(coalesce(p_payload ->> 'sessionName', '')), '');
    v_display_name := nullif(trim(coalesce(p_payload ->> 'displayName', '')), '');
    if v_session_name is null or length(v_session_name) < 3 or length(v_session_name) > 80 then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_SESSION_REQUIRED');
    end if;
    if v_display_name is null then v_display_name := v_session_name; end if;
    if exists (select 1 from public.school_academic_sessions where session_name = v_session_name) then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_SESSION_ALREADY_EXISTS');
    end if;
    begin
      v_starts := nullif(p_payload ->> 'startsOn', '')::date;
      v_ends := nullif(p_payload ->> 'endsOn', '')::date;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'INVALID_ACADEMIC_DATES');
    end;
    if v_ends is not null and v_starts is not null and v_ends < v_starts then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_END_BEFORE_START');
    end if;
    insert into public.school_academic_sessions(
      session_name, display_name, session_status, starts_on, ends_on,
      created_by_person_id, updated_by_person_id
    ) values (
      v_session_name, v_display_name, 'active', v_starts, v_ends,
      v_actor_person_id, v_actor_person_id
    );
    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id, after_data, details
    ) values (
      'person', v_actor_person_id::text, 'academic.session_created',
      'school_academic_session', v_session_name, v_request_id,
      jsonb_build_object('session_name', v_session_name, 'display_name', v_display_name, 'starts_on', v_starts, 'ends_on', v_ends),
      jsonb_build_object('management_session', true)
    );
    return jsonb_build_object('ok', true, 'code', 'ACADEMIC_SESSION_CREATED', 'request_id', v_request_id);
  end if;

  if v_action = 'createterm' then
    v_session_name := nullif(trim(coalesce(p_payload ->> 'academicSession', '')), '');
    v_term_name := nullif(trim(coalesce(p_payload ->> 'term', '')), '');
    if v_session_name is null or v_term_name is null then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TERM_REQUIRED');
    end if;
    if v_term_name not in ('1st Term','2nd Term','3rd Term') then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TERM_NAME_INVALID');
    end if;
    if not exists (select 1 from public.school_academic_sessions where session_name = v_session_name) then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_SESSION_NOT_FOUND');
    end if;
    if exists (select 1 from public.school_academic_terms where academic_session = v_session_name and term_name = v_term_name) then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TERM_ALREADY_EXISTS');
    end if;
    begin
      v_starts := nullif(p_payload ->> 'startsOn', '')::date;
      v_ends := nullif(p_payload ->> 'endsOn', '')::date;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'INVALID_ACADEMIC_DATES');
    end;
    if v_ends is not null and v_starts is not null and v_ends < v_starts then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_END_BEFORE_START');
    end if;
    insert into public.school_academic_terms(
      academic_session, term_name, term_status, is_current, starts_on, ends_on,
      created_by_person_id, updated_by_person_id
    ) values (
      v_session_name, v_term_name, 'open', false, v_starts, v_ends,
      v_actor_person_id, v_actor_person_id
    );
    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id, after_data, details
    ) values (
      'person', v_actor_person_id::text, 'academic.term_created',
      'school_academic_term', v_session_name || ':' || v_term_name, v_request_id,
      jsonb_build_object('academic_session', v_session_name, 'term', v_term_name, 'starts_on', v_starts, 'ends_on', v_ends),
      jsonb_build_object('management_session', true)
    );
    return jsonb_build_object('ok', true, 'code', 'ACADEMIC_TERM_CREATED', 'request_id', v_request_id);
  end if;

  v_session_name := nullif(trim(coalesce(p_payload ->> 'academicSession', '')), '');
  v_term_name := nullif(trim(coalesce(p_payload ->> 'term', '')), '');
  if v_session_name is null or v_term_name is null then
    return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TERM_REQUIRED');
  end if;
  select id, to_jsonb(t) into v_term_id, v_before
  from public.school_academic_terms t
  where t.academic_session = v_session_name and t.term_name = v_term_name
  for update;
  if v_term_id is null then
    return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TERM_NOT_FOUND');
  end if;

  if v_action = 'setcurrent' then
    if (v_before ->> 'term_status') <> 'open' then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TERM_READ_ONLY', 'term_status', v_before ->> 'term_status');
    end if;
    update public.school_academic_terms
    set is_current = false,
        term_status = case when term_status = 'open' then 'closed' else term_status end,
        closed_at = case when term_status = 'open' then coalesce(closed_at, now()) else closed_at end,
        updated_by_person_id = v_actor_person_id,
        updated_at = now()
    where is_current and id <> v_term_id;
    update public.school_academic_terms
    set is_current = true, term_status = 'open', closed_at = null,
        updated_by_person_id = v_actor_person_id, updated_at = now()
    where id = v_term_id;
    insert into public.settings(key, value) values
      ('session', v_session_name), ('term', v_term_name)
    on conflict (key) do update set value = excluded.value;
    perform public.school_registry_refresh_current_allocation_scopes(v_session_name, v_term_name, v_actor_person_id);
    select to_jsonb(t) into v_after from public.school_academic_terms t where t.id = v_term_id;
    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      before_data, after_data, details
    ) values (
      'person', v_actor_person_id::text, 'academic.current_context_changed',
      'school_academic_term', v_term_id::text, v_request_id, v_before, v_after,
      jsonb_build_object('academic_session', v_session_name, 'term', v_term_name, 'settings_updated', true)
    );
    return jsonb_build_object('ok', true, 'code', 'CURRENT_ACADEMIC_TERM_SET', 'current', public.school_academic_current(), 'request_id', v_request_id);
  end if;

  if v_action in ('close','closeaftercorrection') then
    v_reason := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
    if v_reason is null or length(v_reason) < 8 then
      return jsonb_build_object('ok', false, 'code', 'TERM_CLOSE_REASON_REQUIRED');
    end if;
    if (v_before ->> 'is_current')::boolean then
      return jsonb_build_object('ok', false, 'code', 'CURRENT_TERM_REPLACEMENT_REQUIRED');
    end if;
    if (v_before ->> 'term_status') = 'archived' then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TERM_ARCHIVED');
    end if;
    if (v_before ->> 'term_status') = 'closed' then
      return jsonb_build_object('ok', true, 'code', 'ACADEMIC_TERM_ALREADY_CLOSED', 'request_id', v_request_id);
    end if;
    update public.school_academic_terms
    set term_status = 'closed', is_current = false, closed_at = now(),
        updated_by_person_id = v_actor_person_id, updated_at = now()
    where id = v_term_id;
    select to_jsonb(t) into v_after from public.school_academic_terms t where t.id = v_term_id;
    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      before_data, after_data, details
    ) values (
      'person', v_actor_person_id::text, 'academic.term_closed',
      'school_academic_term', v_term_id::text, v_request_id, v_before, v_after,
      jsonb_build_object('reason', v_reason, 'automatic_after_correction', v_action = 'closeaftercorrection')
    );
    return jsonb_build_object('ok', true, 'code', 'ACADEMIC_TERM_CLOSED', 'request_id', v_request_id);
  end if;

  if v_action = 'reopen' then
    v_reason := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
    v_approval := nullif(trim(coalesce(p_payload ->> 'approvalReference', '')), '');
    if v_reason is null or length(v_reason) < 8 then
      return jsonb_build_object('ok', false, 'code', 'TERM_REOPEN_REASON_REQUIRED');
    end if;
    if v_approval is null then
      return jsonb_build_object('ok', false, 'code', 'TERM_REOPEN_APPROVAL_REQUIRED');
    end if;
    if (v_before ->> 'term_status') <> 'closed' then
      return jsonb_build_object('ok', false, 'code', 'TERM_MUST_BE_CLOSED_TO_REOPEN');
    end if;
    update public.school_academic_terms
    set term_status = 'open', is_current = false, closed_at = null,
        last_reopened_at = now(), last_reopened_by_person_id = v_actor_person_id,
        last_reopen_reason = v_reason, last_reopen_approval = v_approval,
        updated_by_person_id = v_actor_person_id, updated_at = now()
    where id = v_term_id;
    select to_jsonb(t) into v_after from public.school_academic_terms t where t.id = v_term_id;
    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      before_data, after_data, details
    ) values (
      'person', v_actor_person_id::text, 'academic.term_reopened',
      'school_academic_term', v_term_id::text, v_request_id, v_before, v_after,
      jsonb_build_object('reason', v_reason, 'approval_reference', v_approval, 'reopen_requires_reclose', true)
    );
    return jsonb_build_object('ok', true, 'code', 'ACADEMIC_TERM_REOPENED_FOR_CORRECTION', 'request_id', v_request_id);
  end if;

  if v_action = 'archive' then
    if (v_before ->> 'is_current')::boolean then
      return jsonb_build_object('ok', false, 'code', 'CURRENT_TERM_CANNOT_BE_ARCHIVED');
    end if;
    if (v_before ->> 'term_status') <> 'closed' then
      return jsonb_build_object('ok', false, 'code', 'ACADEMIC_TERM_MUST_BE_CLOSED');
    end if;
    update public.school_academic_terms
    set term_status = 'archived', updated_by_person_id = v_actor_person_id, updated_at = now()
    where id = v_term_id;
    select to_jsonb(t) into v_after from public.school_academic_terms t where t.id = v_term_id;
    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      before_data, after_data, details
    ) values (
      'person', v_actor_person_id::text, 'academic.term_archived',
      'school_academic_term', v_term_id::text, v_request_id, v_before, v_after,
      jsonb_build_object('management_session', true)
    );
    return jsonb_build_object('ok', true, 'code', 'ACADEMIC_TERM_ARCHIVED', 'request_id', v_request_id);
  end if;

  return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
end;
$function$;

revoke all on function public.school_academic_calendar_management_session_api(uuid, text, text, jsonb)
  from public, authenticated;
grant execute on function public.school_academic_calendar_management_session_api(uuid, text, text, jsonb)
  to anon;


create or replace function public.school_staff_registration_management_session_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_actor_person_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_action text := lower(trim(coalesce(p_action, '')));
  v_registration_id uuid;
  v_registration public.school_staff_registrations%rowtype;
  v_person_id uuid;
  v_staff_id uuid;
  v_staff_number text;
  v_reason text;
  v_status text;
  v_category text := lower(trim(coalesce(p_payload ->> 'staffCategory', 'teaching')));
  v_department text := nullif(trim(coalesce(p_payload ->> 'department', '')), '');
  v_designation text := nullif(trim(coalesce(p_payload ->> 'designation', '')), '');
  v_school_section text := nullif(trim(coalesce(p_payload ->> 'schoolSection', '')), '');
  v_before jsonb;
  v_after jsonb;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;
  v_actor_person_id := wts_internal.central_management_actor(v_session);
  if v_actor_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED');
  end if;

  if v_action = 'list' then
    v_status := lower(trim(coalesce(p_payload ->> 'status', 'pending')));
    if v_status not in ('pending','under_review','approved','rejected','withdrawn','') then
      v_status := 'pending';
    end if;
    return jsonb_build_object(
      'ok', true,
      'registrations', coalesce((
        select jsonb_agg(jsonb_build_object(
          'id', r.id, 'full_name', r.full_name, 'email', r.email,
          'phone', r.phone, 'whatsapp_number', r.whatsapp_number,
          'address', r.address, 'emergency_contact_supplied', r.emergency_contact is not null,
          'has_photo', r.photo_data is not null, 'registration_status', r.registration_status,
          'submitted_at', r.submitted_at, 'reviewed_at', r.reviewed_at,
          'rejection_reason', r.rejection_reason, 'approved_staff_id', r.approved_staff_id
        ) order by r.submitted_at desc)
        from public.school_staff_registrations r
        where v_status = '' or r.registration_status = v_status
      ), '[]'::jsonb)
    );
  end if;

  begin
    v_registration_id := (p_payload ->> 'registrationId')::uuid;
  exception when others then
    return jsonb_build_object('ok', false, 'code', 'REGISTRATION_ID_INVALID');
  end;
  if v_registration_id is null then
    return jsonb_build_object('ok', false, 'code', 'REGISTRATION_ID_REQUIRED');
  end if;
  select * into v_registration
  from public.school_staff_registrations
  where id = v_registration_id
  for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'STAFF_REGISTRATION_NOT_FOUND');
  end if;

  if v_action = 'detail' then
    return jsonb_build_object(
      'ok', true,
      'registration', jsonb_build_object(
        'id', v_registration.id, 'full_name', v_registration.full_name,
        'email', v_registration.email, 'phone', v_registration.phone,
        'whatsapp_number', v_registration.whatsapp_number,
        'address', v_registration.address, 'emergency_contact', v_registration.emergency_contact,
        'photo', v_registration.photo_data, 'registration_status', v_registration.registration_status,
        'submitted_at', v_registration.submitted_at, 'reviewed_at', v_registration.reviewed_at,
        'rejection_reason', v_registration.rejection_reason, 'approved_staff_id', v_registration.approved_staff_id
      )
    );
  end if;

  if v_action = 'underreview' then
    if v_registration.registration_status not in ('pending','under_review') then
      return jsonb_build_object('ok', false, 'code', 'REGISTRATION_NOT_REVIEWABLE');
    end if;
    update public.school_staff_registrations
    set registration_status = 'under_review', reviewed_by_person_id = v_actor_person_id,
        reviewed_at = now(), updated_at = now()
    where id = v_registration.id;
    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      before_data, after_data, details
    ) values (
      'person', v_actor_person_id::text, 'staff.registration_under_review',
      'school_staff_registration', v_registration.id::text, v_request_id,
      jsonb_build_object('registration_status', v_registration.registration_status),
      jsonb_build_object('registration_status', 'under_review'),
      jsonb_build_object('management_session', true)
    );
    return jsonb_build_object('ok', true, 'code', 'STAFF_REGISTRATION_MARKED_UNDER_REVIEW', 'request_id', v_request_id);
  end if;

  if v_action = 'reject' then
    v_reason := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
    if v_reason is null or length(v_reason) < 8 then
      return jsonb_build_object('ok', false, 'code', 'REJECTION_REASON_REQUIRED');
    end if;
    if v_registration.registration_status not in ('pending','under_review') then
      return jsonb_build_object('ok', false, 'code', 'REGISTRATION_NOT_REJECTABLE');
    end if;
    update public.school_staff_registrations
    set registration_status = 'rejected', rejection_reason = v_reason,
        reviewed_by_person_id = v_actor_person_id, reviewed_at = now(), updated_at = now()
    where id = v_registration.id;
    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      before_data, after_data, details
    ) values (
      'person', v_actor_person_id::text, 'staff.registration_rejected',
      'school_staff_registration', v_registration.id::text, v_request_id,
      jsonb_build_object('registration_status', v_registration.registration_status),
      jsonb_build_object('registration_status', 'rejected'),
      jsonb_build_object('reason', v_reason)
    );
    return jsonb_build_object('ok', true, 'code', 'STAFF_REGISTRATION_REJECTED', 'request_id', v_request_id);
  end if;

  if v_action <> 'approve' then
    return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
  end if;
  if v_registration.registration_status = 'approved' then
    select id, staff_number, central_person_id
      into v_staff_id, v_staff_number, v_person_id
    from public.staff_attendance_profiles
    where id = v_registration.approved_staff_id;
    return jsonb_build_object(
      'ok', true, 'code', 'STAFF_REGISTRATION_ALREADY_APPROVED',
      'staff_id', v_staff_id, 'staff_number', v_staff_number, 'person_id', v_person_id
    );
  end if;
  if v_registration.registration_status not in ('pending','under_review') then
    return jsonb_build_object('ok', false, 'code', 'REGISTRATION_NOT_APPROVABLE');
  end if;
  if v_category not in ('teaching','non_teaching','management','contract','casual') then
    return jsonb_build_object('ok', false, 'code', 'STAFF_CATEGORY_INVALID');
  end if;
  if v_designation is null or length(v_designation) > 160 then
    return jsonb_build_object('ok', false, 'code', 'STAFF_POSITION_REQUIRED');
  end if;
  if v_department is not null and length(v_department) > 160 then
    return jsonb_build_object('ok', false, 'code', 'STAFF_DEPARTMENT_INVALID');
  end if;
  if v_school_section is not null and length(v_school_section) > 160 then
    return jsonb_build_object('ok', false, 'code', 'STAFF_SECTION_INVALID');
  end if;

  perform pg_advisory_xact_lock(hashtext(
    coalesce(v_registration.email, '') || '|' || coalesce(v_registration.phone, '') || '|' || coalesce(v_registration.whatsapp_number, '')
  ));
  if exists (
    select 1 from public.staff_attendance_profiles s
    where s.registration_status in ('active','pending','suspended')
      and (lower(coalesce(s.email, '')) = lower(coalesce(v_registration.email, ''))
        or s.phone = v_registration.phone
        or s.whatsapp_number = v_registration.whatsapp_number)
  ) then
    return jsonb_build_object('ok', false, 'code', 'DUPLICATE_STAFF_IDENTITY');
  end if;

  insert into public.school_people(
    full_name, primary_email, primary_phone, photo_path, person_status, metadata
  ) values (
    v_registration.full_name, v_registration.email, v_registration.phone,
    v_registration.photo_data, 'active',
    jsonb_build_object(
      'created_from', 'staff_self_registration',
      'registration_id', v_registration.id
    )
  ) returning id into v_person_id;

  insert into public.staff_attendance_profiles(
    full_name, email, phone, address, staff_category, department, designation,
    photo, school_section, employment_status, attendance_required, metadata,
    registration_source, registration_status, activated_at, central_person_id,
    whatsapp_number, preferred_language
  ) values (
    v_registration.full_name, v_registration.email, v_registration.phone,
    v_registration.address, v_category, v_department, v_designation,
    v_registration.photo_data, v_school_section, 'active', true,
    jsonb_build_object(
      'created_from', 'staff_self_registration',
      'registration_id', v_registration.id,
      'emergency_contact', v_registration.emergency_contact
    ),
    'self_registration', 'active', now(), v_person_id,
    v_registration.whatsapp_number, 'en'
  ) returning id, staff_number into v_staff_id, v_staff_number;

  insert into public.school_identity_accounts(
    person_id, login_email, account_status, identity_source, metadata
  ) values (
    v_person_id, v_registration.email, 'active', 'central_registry',
    jsonb_build_object('approved_from', 'staff_self_registration', 'registration_id', v_registration.id)
  )
  on conflict (person_id) do update set
    login_email = excluded.login_email,
    account_status = 'active',
    identity_source = 'central_registry',
    metadata = public.school_identity_accounts.metadata || excluded.metadata,
    updated_at = now();

  update public.school_staff_registrations
  set registration_status = 'approved', reviewed_by_person_id = v_actor_person_id,
      reviewed_at = now(), approved_staff_id = v_staff_id, updated_at = now()
  where id = v_registration.id;

  select to_jsonb(s) into v_after
  from public.staff_attendance_profiles s where s.id = v_staff_id;
  insert into public.school_registry_audit(
    actor_type, actor_id, action, entity_type, entity_id, request_id,
    before_data, after_data, details
  ) values (
    'person', v_actor_person_id::text, 'staff.registration_approved',
    'staff_attendance_profile', v_staff_id::text, v_request_id,
    jsonb_build_object('registration_id', v_registration.id, 'registration_status', v_registration.registration_status),
    jsonb_build_object('staff_id', v_staff_id, 'staff_number', v_staff_number, 'person_id', v_person_id),
    jsonb_build_object(
      'registration_id', v_registration.id, 'position_assigned', v_designation,
      'department_assigned', v_department, 'school_section_assigned', v_school_section,
      'module_access_requires_separate_management_decision', true
    )
  );
  return jsonb_build_object(
    'ok', true, 'code', 'STAFF_REGISTRATION_APPROVED',
    'staff_id', v_staff_id, 'staff_number', v_staff_number, 'person_id', v_person_id,
    'request_id', v_request_id
  );
end;
$function$;

revoke all on function public.school_staff_registration_management_session_api(uuid, text, text, jsonb)
  from public, authenticated;
grant execute on function public.school_staff_registration_management_session_api(uuid, text, text, jsonb)
  to anon;


create or replace function public.school_registry_sync_allocation_scope(
  p_person_id uuid,
  p_staff_id uuid,
  p_scope_type text,
  p_class_key text,
  p_subject_index integer,
  p_academic_session text,
  p_term text,
  p_enabled boolean,
  p_actor_person_id uuid,
  p_allocation_id uuid,
  p_reason text
)
returns void
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_scope_id uuid;
begin
  if p_enabled then
    select s.id into v_scope_id
    from public.school_staff_access_scopes s
    where s.person_id = p_person_id
      and s.app_code = 'results'
      and s.scope_type = p_scope_type
      and s.class_key = p_class_key
      and s.subject_index is not distinct from p_subject_index
      and s.metadata ->> 'managed_from' = 'central_registry_allocations'
      and s.metadata ->> 'central_allocation_id' = p_allocation_id::text
    order by s.updated_at desc
    limit 1;
    if v_scope_id is null then
      insert into public.school_staff_access_scopes(
        person_id, app_code, scope_type, class_key, subject_index,
        scope_status, effective_from, assigned_by_person_id, assigned_at,
        reason, metadata
      ) values (
        p_person_id, 'results', p_scope_type, p_class_key, p_subject_index,
        'active', now(), p_actor_person_id, now(), p_reason,
        jsonb_build_object(
          'managed_from', 'central_registry_allocations',
          'central_allocation_id', p_allocation_id,
          'academic_session', p_academic_session,
          'term', p_term,
          'staff_id', p_staff_id
        )
      );
    else
      update public.school_staff_access_scopes
      set scope_status = 'active', effective_from = now(), effective_until = null,
          assigned_by_person_id = p_actor_person_id, assigned_at = now(),
          revoked_by_person_id = null, revoked_at = null, revocation_reason = null,
          reason = p_reason,
          metadata = metadata || jsonb_build_object(
            'academic_session', p_academic_session, 'term', p_term, 'staff_id', p_staff_id
          ),
          updated_at = now()
      where id = v_scope_id;
    end if;
  else
    update public.school_staff_access_scopes
    set scope_status = 'revoked', effective_until = coalesce(effective_until, now()),
        revoked_by_person_id = p_actor_person_id, revoked_at = now(),
        revocation_reason = p_reason, updated_at = now()
    where person_id = p_person_id
      and app_code = 'results'
      and metadata ->> 'managed_from' = 'central_registry_allocations'
      and metadata ->> 'central_allocation_id' = p_allocation_id::text
      and scope_status = 'active';
  end if;
end;
$function$;

revoke all on function public.school_registry_sync_allocation_scope(uuid, uuid, text, text, integer, text, text, boolean, uuid, uuid, text)
  from public, anon, authenticated;

create or replace function public.school_registry_sync_class_teacher_role(
  p_person_id uuid,
  p_staff_id uuid,
  p_enabled boolean,
  p_actor_person_id uuid,
  p_reason text
)
returns void
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
begin
  if not exists (select 1 from public.school_system_role_catalog where role_code = 'class_teacher') then
    return;
  end if;
  if p_enabled then
    insert into public.school_staff_role_assignments(
      person_id, role_code, assignment_status, effective_from, effective_until,
      assigned_by_person_id, assigned_at, reason, metadata
    ) values (
      p_person_id, 'class_teacher', 'active', now(), null,
      p_actor_person_id, now(), p_reason,
      jsonb_build_object('managed_from', 'central_registry_allocations', 'staff_id', p_staff_id)
    )
    on conflict (person_id, role_code) do update set
      assignment_status = 'active', effective_from = now(), effective_until = null,
      assigned_by_person_id = p_actor_person_id, assigned_at = now(),
      revoked_by_person_id = null, revoked_at = null, revocation_reason = null,
      reason = p_reason,
      metadata = public.school_staff_role_assignments.metadata || excluded.metadata,
      updated_at = now();
  elsif not exists (
    select 1
    from public.school_staff_class_allocations a
    where a.person_id = p_person_id
      and a.responsibility = 'class_teacher'
      and a.allocation_status = 'active'
  ) then
    update public.school_staff_role_assignments
    set assignment_status = 'revoked', effective_until = coalesce(effective_until, now()),
        revoked_by_person_id = p_actor_person_id, revoked_at = now(),
        revocation_reason = p_reason, updated_at = now()
    where person_id = p_person_id
      and role_code = 'class_teacher'
      and metadata ->> 'managed_from' = 'central_registry_allocations';
  end if;
end;
$function$;

revoke all on function public.school_registry_sync_class_teacher_role(uuid, uuid, boolean, uuid, text)
  from public, anon, authenticated;

create or replace function public.school_registry_refresh_current_allocation_scopes(
  p_academic_session text,
  p_term text,
  p_actor_person_id uuid
)
returns void
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_row record;
begin
  update public.school_staff_role_assignments r
  set assignment_status = 'revoked', effective_until = coalesce(r.effective_until, now()),
      revoked_by_person_id = p_actor_person_id, revoked_at = now(),
      revocation_reason = 'Academic context changed in Central Registry', updated_at = now()
  where r.role_code = 'class_teacher'
    and r.assignment_status = 'active'
    and r.metadata ->> 'managed_from' = 'central_registry_allocations'
    and not exists (
      select 1 from public.school_staff_class_allocations a
      where a.person_id = r.person_id
        and a.academic_session = p_academic_session
        and a.term_name = p_term
        and a.responsibility = 'class_teacher'
        and a.allocation_status = 'active'
    );

  update public.school_staff_access_scopes
  set scope_status = 'revoked', effective_until = coalesce(effective_until, now()),
      revoked_by_person_id = p_actor_person_id, revoked_at = now(),
      revocation_reason = 'Academic context changed in Central Registry', updated_at = now()
  where metadata ->> 'managed_from' = 'central_registry_allocations'
    and scope_status = 'active';

  for v_row in
    select a.*
    from public.school_staff_class_allocations a
    where a.academic_session = p_academic_session
      and a.term_name = p_term
      and a.allocation_status = 'active'
  loop
    perform public.school_registry_sync_allocation_scope(
      v_row.person_id, v_row.staff_id, 'class', v_row.class_key, null,
      v_row.academic_session, v_row.term_name, true, p_actor_person_id, v_row.id, coalesce(v_row.reason, 'Current academic class allocation')
    );
    if v_row.responsibility = 'class_teacher' then
      perform public.school_registry_sync_class_teacher_role(v_row.person_id, v_row.staff_id, true, p_actor_person_id, coalesce(v_row.reason, 'Current academic class allocation'));
    end if;
  end loop;

  for v_row in
    select a.*
    from public.school_staff_subject_allocations a
    where a.academic_session = p_academic_session
      and a.term_name = p_term
      and a.allocation_status = 'active'
  loop
    perform public.school_registry_sync_allocation_scope(
      v_row.person_id, v_row.staff_id, 'subject', v_row.class_key, v_row.subject_index,
      v_row.academic_session, v_row.term_name, true, p_actor_person_id, v_row.id, coalesce(v_row.reason, 'Current academic subject allocation')
    );
  end loop;
end;
$function$;

revoke all on function public.school_registry_refresh_current_allocation_scopes(text, text, uuid)
  from public, anon, authenticated;

create or replace function public.school_staff_allocation_management_session_api(
  p_session_id uuid,
  p_session_secret text,
  p_action text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path to 'pg_catalog', 'extensions', 'public'
as $function$
declare
  v_session jsonb;
  v_current jsonb;
  v_gate jsonb;
  v_actor_person_id uuid;
  v_request_id uuid := gen_random_uuid();
  v_action text := lower(trim(coalesce(p_action, '')));
  v_staff_id uuid;
  v_person_id uuid;
  v_allocation_id uuid;
  v_source_session text;
  v_source_term text;
  v_academic_session text;
  v_term_name text;
  v_class_key text;
  v_responsibility text;
  v_reason text;
  v_enabled boolean;
  v_subject_index integer;
  v_subject_indexes integer[];
  v_count integer := 0;
  v_class_count integer := 0;
  v_subject_count integer := 0;
  v_before jsonb;
  v_after jsonb;
  v_row record;
begin
  v_session := public.school_identity_session_validate(p_session_id, p_session_secret, 'central_registry');
  if coalesce((v_session ->> 'ok')::boolean, false) is not true then
    return v_session;
  end if;
  v_actor_person_id := wts_internal.central_management_actor(v_session);
  if v_actor_person_id is null then
    return jsonb_build_object('ok', false, 'code', 'MANAGEMENT_ACCESS_DENIED');
  end if;

  v_current := public.school_academic_current();
  v_academic_session := coalesce(nullif(trim(coalesce(p_payload ->> 'academicSession', '')), ''), v_current ->> 'academic_session');
  v_term_name := coalesce(nullif(trim(coalesce(p_payload ->> 'term', '')), ''), v_current ->> 'term');

  if v_action = 'read' then
    return jsonb_build_object(
      'ok', true,
      'current', v_current,
      'academic_session', v_academic_session,
      'term', v_term_name,
      'staff', coalesce((
        select jsonb_agg(jsonb_build_object(
          'staff_id', s.id, 'person_id', s.central_person_id,
          'staff_number', s.staff_number, 'full_name', s.full_name,
          'email', s.email, 'designation', s.designation,
          'department', s.department, 'school_section', s.school_section,
          'staff_category', s.staff_category
        ) order by s.full_name)
        from public.staff_attendance_profiles s
        where s.registration_status = 'active' and s.employment_status = 'active'
      ), '[]'::jsonb),
      'classes', coalesce((
        select jsonb_agg(jsonb_build_object(
          'class_key', c.class_key, 'display_name', c.display_name,
          'section', c.section
        ) order by c.sort_order, c.display_name)
        from public.school_classes c where c.is_active
      ), '[]'::jsonb),
      'subjects', coalesce((
        select jsonb_agg(jsonb_build_object(
          'class_key', r.class_key, 'subject_index', r.subject_index,
          'subject_name', r.subject_name
        ) order by r.class_key, r.subject_index)
        from public.result_subject_catalog r
        join public.school_classes c on c.class_key = r.class_key and c.is_active
        where r.active
      ), '[]'::jsonb),
      'class_allocations', coalesce((
        select jsonb_agg(jsonb_build_object(
          'id', a.id, 'staff_id', a.staff_id, 'person_id', a.person_id,
          'staff_number', s.staff_number, 'full_name', s.full_name,
          'academic_session', a.academic_session, 'term', a.term_name,
          'class_key', a.class_key, 'class_name', c.display_name,
          'responsibility', a.responsibility, 'allocation_status', a.allocation_status,
          'assigned_at', a.assigned_at, 'reason', a.reason
        ) order by c.sort_order, c.display_name, s.full_name)
        from public.school_staff_class_allocations a
        join public.staff_attendance_profiles s on s.id = a.staff_id
        join public.school_classes c on c.class_key = a.class_key
        where a.academic_session = v_academic_session and a.term_name = v_term_name
          and (nullif(trim(coalesce(p_payload ->> 'staffId', '')), '') is null or a.staff_id = (p_payload ->> 'staffId')::uuid)
      ), '[]'::jsonb),
      'subject_allocations', coalesce((
        select jsonb_agg(jsonb_build_object(
          'id', a.id, 'staff_id', a.staff_id, 'person_id', a.person_id,
          'staff_number', s.staff_number, 'full_name', s.full_name,
          'academic_session', a.academic_session, 'term', a.term_name,
          'class_key', a.class_key, 'class_name', c.display_name,
          'subject_index', a.subject_index, 'subject_name', r.subject_name,
          'allocation_status', a.allocation_status,
          'assigned_at', a.assigned_at, 'reason', a.reason
        ) order by s.full_name, c.sort_order, c.display_name, r.subject_index)
        from public.school_staff_subject_allocations a
        join public.staff_attendance_profiles s on s.id = a.staff_id
        join public.school_classes c on c.class_key = a.class_key
        join public.result_subject_catalog r on r.class_key = a.class_key and r.subject_index = a.subject_index
        where a.academic_session = v_academic_session and a.term_name = v_term_name
          and (nullif(trim(coalesce(p_payload ->> 'staffId', '')), '') is null or a.staff_id = (p_payload ->> 'staffId')::uuid)
      ), '[]'::jsonb),
      'class_history', coalesce((
        select jsonb_agg(jsonb_build_object(
          'id', a.id, 'staff_id', a.staff_id, 'staff_number', s.staff_number,
          'full_name', s.full_name, 'class_key', a.class_key,
          'responsibility', a.responsibility, 'allocation_status', a.allocation_status,
          'assigned_at', a.assigned_at, 'revoked_at', a.revoked_at,
          'reason', a.reason
        ) order by a.created_at desc)
        from public.school_staff_class_allocations a
        join public.staff_attendance_profiles s on s.id = a.staff_id
        where a.academic_session = v_academic_session and a.term_name = v_term_name
      ), '[]'::jsonb)
    );
  end if;

  if v_action = 'copycontext' then
    v_source_session := nullif(trim(coalesce(p_payload ->> 'sourceAcademicSession', '')), '');
    v_source_term := nullif(trim(coalesce(p_payload ->> 'sourceTerm', '')), '');
    v_reason := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
    if v_source_session is null or v_source_term is null then
      return jsonb_build_object('ok', false, 'code', 'SOURCE_ACADEMIC_CONTEXT_REQUIRED');
    end if;
    if v_source_session = v_academic_session and v_source_term = v_term_name then
      return jsonb_build_object('ok', false, 'code', 'SOURCE_TARGET_CONTEXT_MUST_DIFFER');
    end if;
    if v_reason is null or length(v_reason) < 8 then
      return jsonb_build_object('ok', false, 'code', 'ALLOCATION_REASON_REQUIRED');
    end if;
    if not exists (
      select 1 from public.school_academic_terms
      where academic_session = v_source_session and term_name = v_source_term
    ) then
      return jsonb_build_object('ok', false, 'code', 'SOURCE_ACADEMIC_TERM_NOT_FOUND');
    end if;
    v_gate := public.school_academic_term_write_gate(v_academic_session, v_term_name);
    if coalesce((v_gate ->> 'ok')::boolean, false) is not true then return v_gate; end if;

    for v_row in
      select * from public.school_staff_class_allocations
      where academic_session = v_source_session and term_name = v_source_term and allocation_status = 'active'
      order by created_at
    loop
      if exists (
        select 1 from public.school_staff_class_allocations
        where staff_id = v_row.staff_id and academic_session = v_academic_session
          and term_name = v_term_name and class_key = v_row.class_key
          and responsibility = v_row.responsibility and allocation_status = 'active'
      ) then
        continue;
      end if;
      begin
        insert into public.school_staff_class_allocations(
          staff_id, person_id, academic_session, term_name, class_key,
          responsibility, allocation_status, assigned_by_person_id, assigned_at,
          reason, metadata
        ) values (
          v_row.staff_id, v_row.person_id, v_academic_session, v_term_name, v_row.class_key,
          v_row.responsibility, 'active', v_actor_person_id, now(), v_reason,
          jsonb_build_object('copied_from_allocation_id', v_row.id, 'copied_from_session', v_source_session, 'copied_from_term', v_source_term)
        ) returning id into v_allocation_id;
      exception when unique_violation then
        continue;
      end;
      perform public.school_registry_sync_allocation_scope(
        v_row.person_id, v_row.staff_id, 'class', v_row.class_key, null,
        v_academic_session, v_term_name, true, v_actor_person_id, v_allocation_id, v_reason
      );
      if v_row.responsibility = 'class_teacher' then
        perform public.school_registry_sync_class_teacher_role(v_row.person_id, v_row.staff_id, true, v_actor_person_id, v_reason);
      end if;
      v_class_count := v_class_count + 1;
    end loop;

    for v_row in
      select * from public.school_staff_subject_allocations
      where academic_session = v_source_session and term_name = v_source_term and allocation_status = 'active'
      order by created_at
    loop
      if exists (
        select 1 from public.school_staff_subject_allocations
        where staff_id = v_row.staff_id and academic_session = v_academic_session
          and term_name = v_term_name and class_key = v_row.class_key
          and subject_index = v_row.subject_index and allocation_status = 'active'
      ) then
        continue;
      end if;
      insert into public.school_staff_subject_allocations(
        staff_id, person_id, academic_session, term_name, class_key, subject_index,
        allocation_status, assigned_by_person_id, assigned_at, reason, metadata
      ) values (
        v_row.staff_id, v_row.person_id, v_academic_session, v_term_name, v_row.class_key, v_row.subject_index,
        'active', v_actor_person_id, now(), v_reason,
        jsonb_build_object('copied_from_allocation_id', v_row.id, 'copied_from_session', v_source_session, 'copied_from_term', v_source_term)
      ) returning id into v_allocation_id;
      perform public.school_registry_sync_allocation_scope(
        v_row.person_id, v_row.staff_id, 'subject', v_row.class_key, v_row.subject_index,
        v_academic_session, v_term_name, true, v_actor_person_id, v_allocation_id, v_reason
      );
      v_subject_count := v_subject_count + 1;
    end loop;

    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id, details
    ) values (
      'person', v_actor_person_id::text, 'staff.allocations_copied',
      'school_academic_term', v_academic_session || ':' || v_term_name, v_request_id,
      jsonb_build_object(
        'source_session', v_source_session, 'source_term', v_source_term,
        'class_allocations_copied', v_class_count,
        'subject_allocations_copied', v_subject_count,
        'reason', v_reason
      )
    );
    return jsonb_build_object(
      'ok', true, 'code', 'ALLOCATIONS_COPIED',
      'class_allocations_copied', v_class_count,
      'subject_allocations_copied', v_subject_count,
      'request_id', v_request_id
    );
  end if;

  if v_action = 'setclass' then
    begin
      v_staff_id := (p_payload ->> 'staffId')::uuid;
      v_allocation_id := nullif(p_payload ->> 'allocationId', '')::uuid;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'STAFF_OR_ALLOCATION_ID_INVALID');
    end;
    v_class_key := nullif(trim(coalesce(p_payload ->> 'classKey', '')), '');
    v_responsibility := lower(trim(coalesce(p_payload ->> 'responsibility', 'class_teacher')));
    begin
      v_enabled := coalesce((p_payload ->> 'enabled')::boolean, true);
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'ALLOCATION_ENABLED_INVALID');
    end;
    v_reason := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
    if v_staff_id is null or v_class_key is null then
      return jsonb_build_object('ok', false, 'code', 'STAFF_AND_CLASS_REQUIRED');
    end if;
    if v_responsibility not in ('class_teacher','assistant_class_teacher') then
      return jsonb_build_object('ok', false, 'code', 'CLASS_RESPONSIBILITY_INVALID');
    end if;
    if v_reason is null or length(v_reason) < 8 then
      return jsonb_build_object('ok', false, 'code', 'ALLOCATION_REASON_REQUIRED');
    end if;
    select central_person_id into v_person_id
    from public.staff_attendance_profiles
    where id = v_staff_id and registration_status = 'active' and employment_status = 'active';
    if v_person_id is null then
      return jsonb_build_object('ok', false, 'code', 'STAFF_NOT_ACTIVE');
    end if;
    if not exists (select 1 from public.school_classes where class_key = v_class_key and is_active) then
      return jsonb_build_object('ok', false, 'code', 'ACTIVE_CLASS_NOT_FOUND');
    end if;
    v_gate := public.school_academic_term_write_gate(v_academic_session, v_term_name);
    if coalesce((v_gate ->> 'ok')::boolean, false) is not true then return v_gate; end if;

    perform pg_advisory_xact_lock(hashtext(v_staff_id::text || '|' || v_academic_session || '|' || v_term_name || '|' || v_class_key));

    if v_enabled then
      if v_responsibility = 'class_teacher' and exists (
        select 1 from public.school_staff_class_allocations a
        where a.academic_session = v_academic_session and a.term_name = v_term_name
          and a.class_key = v_class_key and a.responsibility = 'class_teacher'
          and a.allocation_status = 'active' and a.staff_id <> v_staff_id
      ) then
        return jsonb_build_object('ok', false, 'code', 'CLASS_MAIN_TEACHER_ALREADY_ASSIGNED');
      end if;
      if exists (
        select 1 from public.school_staff_class_allocations a
        where a.staff_id = v_staff_id and a.academic_session = v_academic_session
          and a.term_name = v_term_name and a.class_key = v_class_key
          and a.responsibility = v_responsibility and a.allocation_status = 'active'
      ) then
        return jsonb_build_object('ok', true, 'code', 'CLASS_ALLOCATION_ALREADY_ACTIVE');
      end if;
      begin
        insert into public.school_staff_class_allocations(
          staff_id, person_id, academic_session, term_name, class_key,
          responsibility, allocation_status, assigned_by_person_id, assigned_at,
          reason, metadata
        ) values (
          v_staff_id, v_person_id, v_academic_session, v_term_name, v_class_key,
          v_responsibility, 'active', v_actor_person_id, now(), v_reason,
          jsonb_build_object('managed_from', 'central_registry_allocations')
        ) returning id into v_allocation_id;
      exception when unique_violation then
        if v_responsibility = 'class_teacher' then
          return jsonb_build_object('ok', false, 'code', 'CLASS_MAIN_TEACHER_ALREADY_ASSIGNED');
        end if;
        return jsonb_build_object('ok', false, 'code', 'CLASS_ALLOCATION_ALREADY_ACTIVE');
      end;
      perform public.school_registry_sync_allocation_scope(
        v_person_id, v_staff_id, 'class', v_class_key, null,
        v_academic_session, v_term_name, true, v_actor_person_id, v_allocation_id, v_reason
      );
      if v_responsibility = 'class_teacher' then
        perform public.school_registry_sync_class_teacher_role(v_person_id, v_staff_id, true, v_actor_person_id, v_reason);
      end if;
      select to_jsonb(a) into v_after from public.school_staff_class_allocations a where a.id = v_allocation_id;
      insert into public.school_registry_audit(
        actor_type, actor_id, action, entity_type, entity_id, request_id, after_data, details
      ) values (
        'person', v_actor_person_id::text, 'staff.class_allocation_assigned',
        'school_staff_class_allocation', v_allocation_id::text, v_request_id, v_after,
        jsonb_build_object('staff_id', v_staff_id, 'person_id', v_person_id, 'class_key', v_class_key,
          'responsibility', v_responsibility, 'academic_session', v_academic_session, 'term', v_term_name)
      );
      return jsonb_build_object('ok', true, 'code', 'CLASS_ALLOCATION_ASSIGNED', 'allocation_id', v_allocation_id, 'request_id', v_request_id);
    end if;

    select a.id, a.person_id, a.responsibility, to_jsonb(a)
      into v_allocation_id, v_person_id, v_responsibility, v_before
    from public.school_staff_class_allocations a
    where (v_allocation_id is null or a.id = v_allocation_id)
      and a.staff_id = v_staff_id
      and a.academic_session = v_academic_session
      and a.term_name = v_term_name
      and (v_class_key is null or a.class_key = v_class_key)
      and a.responsibility = v_responsibility
      and a.allocation_status = 'active'
    order by a.created_at desc
    limit 1
    for update;
    if v_allocation_id is null then
      return jsonb_build_object('ok', true, 'code', 'CLASS_ALLOCATION_ALREADY_REVOKED');
    end if;
    update public.school_staff_class_allocations
    set allocation_status = 'revoked', effective_until = now(),
        revoked_by_person_id = v_actor_person_id, revoked_at = now(),
        revocation_reason = v_reason, updated_at = now()
    where id = v_allocation_id;
    perform public.school_registry_sync_allocation_scope(
      v_person_id, v_staff_id, 'class', v_class_key, null,
      v_academic_session, v_term_name, false, v_actor_person_id, v_allocation_id, v_reason
    );
    if v_responsibility = 'class_teacher' then
      perform public.school_registry_sync_class_teacher_role(v_person_id, v_staff_id, false, v_actor_person_id, v_reason);
    end if;
    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id,
      before_data, after_data, details
    ) values (
      'person', v_actor_person_id::text, 'staff.class_allocation_revoked',
      'school_staff_class_allocation', v_allocation_id::text, v_request_id, v_before,
      (select to_jsonb(a) from public.school_staff_class_allocations a where a.id = v_allocation_id),
      jsonb_build_object('staff_id', v_staff_id, 'person_id', v_person_id, 'class_key', v_class_key,
        'responsibility', v_responsibility, 'academic_session', v_academic_session, 'term', v_term_name, 'reason', v_reason)
    );
    return jsonb_build_object('ok', true, 'code', 'CLASS_ALLOCATION_REVOKED', 'allocation_id', v_allocation_id, 'request_id', v_request_id);
  end if;

  if v_action = 'setsubjects' then
    begin
      v_staff_id := (p_payload ->> 'staffId')::uuid;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'STAFF_ID_INVALID');
    end;
    v_class_key := nullif(trim(coalesce(p_payload ->> 'classKey', '')), '');
    v_reason := nullif(trim(coalesce(p_payload ->> 'reason', '')), '');
    if v_staff_id is null or v_class_key is null then
      return jsonb_build_object('ok', false, 'code', 'STAFF_AND_CLASS_REQUIRED');
    end if;
    if not (p_payload ? 'subjectIndexes') then
      return jsonb_build_object('ok', false, 'code', 'SUBJECT_SELECTION_REQUIRED');
    end if;
    if v_reason is null or length(v_reason) < 8 then
      return jsonb_build_object('ok', false, 'code', 'ALLOCATION_REASON_REQUIRED');
    end if;
    begin
      select coalesce(array_agg(distinct value::integer order by value::integer), array[]::integer[])
        into v_subject_indexes
      from jsonb_array_elements_text(p_payload -> 'subjectIndexes') value;
    exception when others then
      return jsonb_build_object('ok', false, 'code', 'SUBJECT_SELECTION_INVALID');
    end;
    if cardinality(v_subject_indexes) > 100 then
      return jsonb_build_object('ok', false, 'code', 'TOO_MANY_SUBJECTS_SELECTED');
    end if;
    select central_person_id into v_person_id
    from public.staff_attendance_profiles
    where id = v_staff_id and registration_status = 'active' and employment_status = 'active';
    if v_person_id is null then
      return jsonb_build_object('ok', false, 'code', 'STAFF_NOT_ACTIVE');
    end if;
    if not exists (select 1 from public.school_classes where class_key = v_class_key and is_active) then
      return jsonb_build_object('ok', false, 'code', 'ACTIVE_CLASS_NOT_FOUND');
    end if;
    if exists (
      select 1 from unnest(v_subject_indexes) selected_index
      where not exists (
        select 1 from public.result_subject_catalog r
        where r.class_key = v_class_key and r.subject_index = selected_index and r.active
      )
    ) then
      return jsonb_build_object('ok', false, 'code', 'ACTIVE_RESULT_SUBJECT_NOT_FOUND');
    end if;
    v_gate := public.school_academic_term_write_gate(v_academic_session, v_term_name);
    if coalesce((v_gate ->> 'ok')::boolean, false) is not true then return v_gate; end if;
    perform pg_advisory_xact_lock(hashtext(v_staff_id::text || '|' || v_academic_session || '|' || v_term_name || '|' || v_class_key));

    for v_row in
      select * from public.school_staff_subject_allocations a
      where a.staff_id = v_staff_id and a.academic_session = v_academic_session
        and a.term_name = v_term_name and a.class_key = v_class_key
        and a.allocation_status = 'active'
        and not (a.subject_index = any(v_subject_indexes))
      for update
    loop
      update public.school_staff_subject_allocations
      set allocation_status = 'revoked', effective_until = now(),
          revoked_by_person_id = v_actor_person_id, revoked_at = now(),
          revocation_reason = v_reason, updated_at = now()
      where id = v_row.id;
      perform public.school_registry_sync_allocation_scope(
        v_row.person_id, v_row.staff_id, 'subject', v_row.class_key, v_row.subject_index,
        v_row.academic_session, v_row.term_name, false, v_actor_person_id, v_row.id, v_reason
      );
      v_count := v_count + 1;
    end loop;

    for v_subject_index in select distinct unnest(v_subject_indexes)
    loop
      select a.id into v_allocation_id
      from public.school_staff_subject_allocations a
      where a.staff_id = v_staff_id and a.academic_session = v_academic_session
        and a.term_name = v_term_name and a.class_key = v_class_key
        and a.subject_index = v_subject_index and a.allocation_status = 'active'
      for update;
      if v_allocation_id is null then
        insert into public.school_staff_subject_allocations(
          staff_id, person_id, academic_session, term_name, class_key, subject_index,
          allocation_status, assigned_by_person_id, assigned_at, reason, metadata
        ) values (
          v_staff_id, v_person_id, v_academic_session, v_term_name, v_class_key, v_subject_index,
          'active', v_actor_person_id, now(), v_reason,
          jsonb_build_object('managed_from', 'central_registry_allocations')
        ) returning id into v_allocation_id;
        v_subject_count := v_subject_count + 1;
      end if;
      perform public.school_registry_sync_allocation_scope(
        v_person_id, v_staff_id, 'subject', v_class_key, v_subject_index,
        v_academic_session, v_term_name, true, v_actor_person_id, v_allocation_id, v_reason
      );
    end loop;

    insert into public.school_registry_audit(
      actor_type, actor_id, action, entity_type, entity_id, request_id, details
    ) values (
      'person', v_actor_person_id::text, 'staff.subject_allocations_replaced',
      'staff_attendance_profile', v_staff_id::text, v_request_id,
      jsonb_build_object(
        'staff_id', v_staff_id, 'person_id', v_person_id, 'class_key', v_class_key,
        'academic_session', v_academic_session, 'term', v_term_name,
        'selected_subject_indexes', v_subject_indexes,
        'revoked_count', v_count, 'created_count', v_subject_count, 'reason', v_reason
      )
    );
    return jsonb_build_object(
      'ok', true, 'code', 'SUBJECT_ALLOCATIONS_SAVED',
      'revoked_count', v_count, 'created_count', v_subject_count,
      'request_id', v_request_id
    );
  end if;

  return jsonb_build_object('ok', false, 'code', 'UNKNOWN_ACTION');
end;
$function$;

revoke all on function public.school_staff_allocation_management_session_api(uuid, text, text, jsonb)
  from public, authenticated;
grant execute on function public.school_staff_allocation_management_session_api(uuid, text, text, jsonb)
  to anon;


-- Central Registry owns module entry decisions. Specialist modules own their
-- technical action permissions, so a new module-entry grant may have an empty
-- permissions array. Existing production permission arrays are preserved by
-- the existing access adapter and are not rewritten here.
do $migration$
declare
  v_definition text;
begin
  select pg_get_functiondef(p.oid)
    into v_definition
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname = 'school_access_management_write_session_api'
    and pg_get_function_identity_arguments(p.oid) =
      'p_session_id uuid, p_session_secret text, p_action text, p_payload jsonb';
  if v_definition is null then
    raise exception 'CENTRAL_ACCESS_WRITE_FUNCTION_NOT_FOUND';
  end if;
  if position('AT_LEAST_ONE_ACTION_PERMISSION_REQUIRED' in v_definition) = 0 then
    return;
  end if;
  v_definition := replace(
    v_definition,
    'if v_enabled and v_app_code <> ''staff_self_service'' and cardinality(v_permissions) = 0 then',
    'if false then'
  );
  execute v_definition;
end;
$migration$;
