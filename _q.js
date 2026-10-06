const u = 'https://wuftzyeajmsxdrbwaawl.supabase.co/rest/v1/school_classes?select=*';
const k = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind1ZnR6eWVham1zeGRyYndhYXdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4NjczNTgsImV4cCI6MjA4OTQ0MzM1OH0.QUeDRP1IpHCjvecqAOEZAqmMalEFlCLXylZP5D5iLog';
fetch(u, { headers: { apikey: k, Authorization: `Bearer ${k}` } })
  .then(r => r.json())
  .then(j => console.log(JSON.stringify(j, null, 2)));
