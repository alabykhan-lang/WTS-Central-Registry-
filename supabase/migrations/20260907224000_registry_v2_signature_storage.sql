-- Private signature storage. Browser never receives a service-role key.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('staff-signatures','staff-signatures',false,2097152,array['image/png','image/jpeg','image/webp'])
on conflict (id) do update set public=false,file_size_limit=2097152,allowed_mime_types=excluded.allowed_mime_types;
