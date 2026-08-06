-- Defense in depth: the management-code table is never directly readable or
-- writable through the Data API. Guarded RPCs run as the table owner.
drop policy if exists school_identity_management_codes_no_direct_access
  on public.school_identity_management_codes;
create policy school_identity_management_codes_no_direct_access
  on public.school_identity_management_codes
  for all
  to public
  using (false)
  with check (false);
