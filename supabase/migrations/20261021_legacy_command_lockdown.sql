-- 20261021_legacy_command_lockdown.sql
-- Purpose: close the unauthenticated legacy command RPCs that bypass the
--          central-registry / result-portal authorization model.
--
-- Background
--   These functions are SECURITY DEFINER and were created with the Postgres
--   default ACL, which grants EXECUTE to PUBLIC (and an explicit grant to
--   anon/authenticated). They perform score, student, fee, remark, publish and
--   audit writes WITHOUT validating a session, capability, class scope or the
--   staff write switch, so the public publishable key (shipped inside the
--   portal HTML) could call them directly.
--
--   The current application never calls any of them (verified by grep across
--   wts-result-system, WTS-Central-Registry- and WTS-School-Platform). They are
--   leftovers from the earlier "ChatGPT control center" workflow.
--
-- Effect
--   EXECUTE is removed from PUBLIC, anon and authenticated. service_role keeps
--   its explicit grant, so a server-side workflow can still call them.
--   No data is changed. Reversible: grant execute on function ... to anon;
--
-- Applied: 2026-10-21 (Supabase project wuftzyeajmsxdrbwaawl)

begin;

revoke execute on function public.record_score_command(text,text,integer,text,numeric,text,text,text) from public, anon, authenticated;
revoke execute on function public.record_bulk_scores_command(text,text,text,jsonb,text,text,text,text) from public, anon, authenticated;
revoke execute on function public.record_score_by_student_id_command(uuid,text,integer,text,numeric,text,text,text) from public, anon, authenticated;
revoke execute on function public.record_score_by_subject_command(text,text,text,text,numeric,text,text,text,text) from public, anon, authenticated;

revoke execute on function public.add_student_command(text,text,text,text,text,text,text,text,text,text) from public, anon, authenticated;
revoke execute on function public.update_student_command(text,text,jsonb,text,text,text) from public, anon, authenticated;
revoke execute on function public.archive_student_command(text,text,text,text,text,text) from public, anon, authenticated;
revoke execute on function public.transfer_student_command(text,text,text,text,boolean,text,text,text) from public, anon, authenticated;

revoke execute on function public.record_fee_command(text,text,text,numeric,numeric,numeric,numeric,text,text,text,text) from public, anon, authenticated;
revoke execute on function public.record_remarks_command(text,text,text,text,text,text,integer,integer,text,text,text) from public, anon, authenticated;
revoke execute on function public.record_trait_command(text,text,text,text,integer,text,text,text,text) from public, anon, authenticated;
revoke execute on function public.bulk_record_trait_command(text,text,text,integer,text,text,text,text) from public, anon, authenticated;

revoke execute on function public.create_teacher_score_submission_command(text,text,text,jsonb,text,text,text,text) from public, anon, authenticated;
revoke execute on function public.approve_teacher_score_submission_command(uuid,text,text) from public, anon, authenticated;
revoke execute on function public.list_teacher_score_submissions_command(text,integer) from public, anon, authenticated;

revoke execute on function public.set_subject_published_command(text,text,boolean,text,text,text,text) from public, anon, authenticated;
revoke execute on function public.upsert_subject_catalog_command(text,integer,text,text[],boolean,text,text) from public, anon, authenticated;
revoke execute on function public.sync_result_subject_catalog_from_settings() from public, anon, authenticated;

revoke execute on function public.undo_score_audit_entry_command(uuid,text,text) from public, anon, authenticated;

revoke execute on function public.wts_sync_portfolio_designation() from public, anon, authenticated;
revoke execute on function public.handle_new_staff_portal_user() from public, anon, authenticated;

commit;
