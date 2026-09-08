-- Registry v2 rollout identity correction.
-- Preserve every historical row while ensuring the verified operational
-- Omololu identity is the only school-facing active staff identity.

create table if not exists public.school_identity_consolidations (
  redundant_person_id uuid primary key references public.school_people(id),
  canonical_person_id uuid not null references public.school_people(id),
  redundant_staff_id uuid references public.staff_attendance_profiles(id),
  canonical_staff_id uuid references public.staff_attendance_profiles(id),
  consolidation_status text not null default 'active' check (consolidation_status in ('active','reversed')),
  reason text not null,
  evidence jsonb not null default '{}'::jsonb,
  consolidated_at timestamptz not null default now(),
  metadata jsonb not null default '{}'::jsonb,
  check (redundant_person_id <> canonical_person_id)
);

create index if not exists school_identity_consolidations_canonical_idx
  on public.school_identity_consolidations(canonical_person_id, consolidation_status);
create index if not exists school_identity_consolidations_redundant_staff_idx
  on public.school_identity_consolidations(redundant_staff_id)
  where redundant_staff_id is not null;
create index if not exists school_identity_consolidations_canonical_staff_idx
  on public.school_identity_consolidations(canonical_staff_id)
  where canonical_staff_id is not null;

alter table public.school_identity_consolidations enable row level security;
revoke all on table public.school_identity_consolidations from public, anon, authenticated;

comment on table public.school_identity_consolidations is
  'Auditable, non-destructive aliases from archived duplicate identities to the canonical operational identity.';

do $migration$
declare
  v_canonical_person uuid;
  v_canonical_staff uuid;
  v_redundant_person uuid;
  v_redundant_staff uuid;
  v_redundant_account uuid;
  v_before jsonb;
begin
  select s.central_person_id,s.id
    into v_canonical_person,v_canonical_staff
  from public.staff_attendance_profiles s
  join public.school_people p on p.id=s.central_person_id
  join public.school_identity_accounts i on i.person_id=p.id
  where s.staff_number='WTS/STF/000008'
    and p.institutional_classification='system_owner'
    and p.person_status='active'
    and i.account_status='active'
    and exists (
      select 1 from public.school_identity_credentials c
      where c.identity_account_id=i.id and c.person_id=p.id
        and c.credential_status='active' and c.last_login_at is not null
    )
  order by s.created_at
  limit 1;

  select s.central_person_id,s.id,i.id
    into v_redundant_person,v_redundant_staff,v_redundant_account
  from public.staff_attendance_profiles s
  join public.school_people p on p.id=s.central_person_id
  join public.school_identity_accounts i on i.person_id=p.id
  where s.staff_number='WTS/STF/000013'
    and p.institutional_classification='ordinary_staff'
    and not exists (
      select 1 from public.school_identity_credentials c
      where c.identity_account_id=i.id and c.person_id=p.id
        and (c.credential_status='active' or c.last_login_at is not null)
    )
  order by s.created_at
  limit 1;

  -- Other installations may not contain this verified duplicate pair.
  if v_canonical_person is null or v_redundant_person is null
     or v_canonical_person=v_redundant_person then
    return;
  end if;

  -- Never silently retire an identity that acquired a real current duty after
  -- the readiness review. Such a change requires explicit reassignment first.
  if exists(select 1 from public.school_staff_class_allocations a where a.person_id=v_redundant_person and a.allocation_status='active')
     or exists(select 1 from public.school_staff_subject_allocations a where a.person_id=v_redundant_person and a.allocation_status='active') then
    raise exception using errcode='P0001',message='REDUNDANT_IDENTITY_HAS_ACTIVE_ALLOCATIONS';
  end if;

  select jsonb_build_object(
    'personStatus',p.person_status,'accountStatus',i.account_status,
    'registrationStatus',s.registration_status,'employmentStatus',s.employment_status,
    'credentialCount',(select count(*) from public.school_identity_credentials c where c.person_id=p.id),
    'grantCount',(select count(*) from public.school_access_grants g where g.person_id=p.id),
    'cardCount',(select count(*) from public.staff_cards c where c.staff_id=s.id)
  ) into v_before
  from public.school_people p
  join public.staff_attendance_profiles s on s.central_person_id=p.id
  join public.school_identity_accounts i on i.person_id=p.id
  where p.id=v_redundant_person and s.id=v_redundant_staff and i.id=v_redundant_account;

  insert into public.school_identity_consolidations(
    redundant_person_id,canonical_person_id,redundant_staff_id,canonical_staff_id,
    reason,evidence,metadata
  ) values (
    v_redundant_person,v_canonical_person,v_redundant_staff,v_canonical_staff,
    'Verified duplicate Omololu staff identity archived during Registry v2 rollout',
    v_before,
    jsonb_build_object('source','verified_production_identity_review','preserveHistoricalReferences',true)
  ) on conflict(redundant_person_id) do update set
    canonical_person_id=excluded.canonical_person_id,
    redundant_staff_id=excluded.redundant_staff_id,
    canonical_staff_id=excluded.canonical_staff_id,
    consolidation_status='active',reason=excluded.reason,
    evidence=public.school_identity_consolidations.evidence||excluded.evidence,
    metadata=public.school_identity_consolidations.metadata||excluded.metadata;

  -- Remove technical wording from all staff-facing presentation while keeping
  -- institutional_classification and protected grants intact for authorization.
  update public.staff_attendance_profiles
  set full_name=coalesce((select p.full_name from public.school_people p where p.id=v_canonical_person),full_name),
      designation=case when lower(coalesce(designation,'')) ~ '(super[ _-]*administrator|system[ _-]*owner|developer)' then null else designation end,
      public_display_name=coalesce((select p.full_name from public.school_people p where p.id=v_canonical_person),public_display_name),
      public_display_role=case when lower(coalesce(public_display_role,'')) ~ '(super[ _-]*administrator|system[ _-]*owner|developer)' then null else public_display_role end,
      metadata=metadata||jsonb_build_object('technicalPrivilegePresentation','separated'),updated_at=now()
  where id=v_canonical_staff;
  update public.user_profiles u
  set full_name=p.full_name
  from public.school_people p
  where u.id=(select s.user_profile_id from public.staff_attendance_profiles s where s.id=v_canonical_staff)
    and p.id=v_canonical_person
    and u.full_name is distinct from p.full_name;
  update public.school_people
  set metadata=metadata||jsonb_build_object('technical_privilege',jsonb_build_object('classification',institutional_classification,'presentation','security_and_audit_only')),updated_at=now()
  where id=v_canonical_person;

  update public.school_identity_sessions
  set revoked_at=coalesce(revoked_at,now()),revocation_reason=coalesce(revocation_reason,'Identity consolidated into canonical operational account')
  where person_id=v_redundant_person and revoked_at is null;
  update public.school_identity_credentials
  set credential_status='archived',updated_at=now()
  where person_id=v_redundant_person and credential_status<>'archived';
  update public.school_identity_accounts
  set account_status='archived',metadata=metadata||jsonb_build_object('consolidated_into_person_id',v_canonical_person),updated_at=now()
  where id=v_redundant_account;
  -- Keep the legacy profile row for foreign keys and audit history, but remove
  -- its independent password path so the archived duplicate cannot sign in.
  update public.user_profiles
  set pw_hash=null
  where id=(select s.user_profile_id from public.staff_attendance_profiles s where s.id=v_redundant_staff);
  update public.school_identity_management_codes
  set revoked_at=coalesce(revoked_at,now()),reason=coalesce(reason,'Identity consolidated into canonical operational account'),updated_at=now()
  where person_id=v_redundant_person and used_at is null and revoked_at is null;
  update public.school_access_grants
  set grant_status='revoked',valid_until=coalesce(valid_until,now()),revoked_at=coalesce(revoked_at,now()),
      revocation_reason=coalesce(revocation_reason,'Identity consolidated into canonical operational account'),updated_at=now()
  where person_id=v_redundant_person and grant_status in ('active','suspended');
  update public.school_staff_access_scopes
  set scope_status='revoked',effective_until=coalesce(effective_until,now()),revoked_at=coalesce(revoked_at,now()),
      revocation_reason=coalesce(revocation_reason,'Identity consolidated into canonical operational account'),updated_at=now()
  where person_id=v_redundant_person and scope_status='active';
  update public.staff_cards
  set status='revoked',disabled_at=coalesce(disabled_at,now()),disabled_reason=coalesce(disabled_reason,'Identity consolidated into canonical operational account'),updated_at=now()
  where staff_id=v_redundant_staff and status in ('active','pending','suspended');
  update public.attendance_admin_clients
  set status='retired',session_expires_at=now(),metadata=metadata||jsonb_build_object('consolidated_into_person_id',v_canonical_person),updated_at=now()
  where central_person_id=v_redundant_person and status<>'retired';
  update public.school_person_roles
  set role_status='ended',ended_at=coalesce(ended_at,now()),metadata=metadata||jsonb_build_object('consolidated_into_person_id',v_canonical_person),updated_at=now()
  where person_id=v_redundant_person and role_status='active';
  update public.staff_attendance_profiles
  set registration_status='archived',employment_status='exited',archived_at=coalesce(archived_at,now()),
      public_visibility_approved=false,
      metadata=metadata||jsonb_build_object('directory_suppressed',true,'consolidated_into_person_id',v_canonical_person),updated_at=now()
  where id=v_redundant_staff;
  update public.school_people
  set person_status='archived',archived_at=coalesce(archived_at,now()),
      archived_reason=coalesce(archived_reason,'Duplicate identity consolidated into canonical operational account'),
      metadata=metadata||jsonb_build_object('consolidated_into_person_id',v_canonical_person,'historical_references_preserved',true),updated_at=now()
  where id=v_redundant_person;

  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,before_data,after_data,details)
  values(
    'system','registry_v2_migration','identity.duplicate_consolidated','school_identity_consolidations',v_redundant_person::text,
    v_before,
    jsonb_build_object('personStatus','archived','accountStatus','archived','registrationStatus','archived','employmentStatus','exited'),
    jsonb_build_object('canonicalPersonId',v_canonical_person,'canonicalStaffId',v_canonical_staff,'technicalPrivilegePreserved',true,'historicalReferencesPreserved',true,'legacyCredentialDisabled',true)
  );
  insert into public.school_registry_audit(actor_type,actor_id,action,entity_type,entity_id,details)
  values(
    'system','registry_v2_migration','identity.technical_privilege_presentation_separated','school_people',v_canonical_person::text,
    jsonb_build_object('institutionalClassification','system_owner','visibleAsSchoolPortfolio',false,'authorizationPreserved',true)
  );
end
$migration$;
