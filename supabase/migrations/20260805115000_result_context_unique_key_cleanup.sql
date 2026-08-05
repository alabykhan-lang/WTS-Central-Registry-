-- Replace the pre-context uniqueness keys with the context-aware keys.
alter table public.scores drop constraint if exists scores_student_subject_term_key;
alter table public.traits drop constraint if exists traits_student_type_name_term_key;
alter table public.traits drop constraint if exists traits_upsert_key;
alter table public.remarks drop constraint if exists remarks_student_term_key;
alter table public.remarks drop constraint if exists remarks_upsert_key;
alter table public.fees drop constraint if exists fees_student_term_key;
alter table public.fees drop constraint if exists fees_upsert_key;
alter table public.published_subjects drop constraint if exists published_subjects_class_key_term_subject_index_key;
