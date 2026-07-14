"use strict";(()=>{const W=window.WTSRegistry,R=window.WTSRecords,{$,$$,state,toast,auth,view,signOut}=W;

function addArchiveControls(){
  const studentCard=$('[data-action="addStudent"]')?.closest('.card');
  if(studentCard&&!studentCard.querySelector('[data-manage-students]')){
    const row=document.createElement('div');row.className='button-row';row.style.marginTop='10px';
    const manage=document.createElement('button');manage.type='button';manage.className='ghost';manage.dataset.manageStudents='true';manage.textContent='Manage / archive students';
    row.appendChild(manage);studentCard.appendChild(row);
  }
  const studentHead=$('#view-students .section-head');
  if(studentHead&&!studentHead.querySelector('#showArchivedStudents')){
    const actions=document.createElement('div');actions.className='actions';
    const archived=document.createElement('button');archived.type='button';archived.className='ghost';archived.id='showArchivedStudents';archived.textContent='Show archived students';
    const admit=document.createElement('button');admit.type='button';admit.className='primary';admit.dataset.action='addStudent';admit.textContent='Admit student';
    const old=studentHead.querySelector('[data-action="addStudent"]');if(old)old.remove();
    actions.append(archived,admit);studentHead.appendChild(actions);
  }
}

addArchiveControls();
$$('.nav').forEach(b=>b.onclick=()=>view(b.dataset.view));
$$('[data-open]').forEach(b=>b.onclick=()=>view(b.dataset.open));
$$('[data-manage-students]').forEach(b=>b.onclick=()=>{view('students');$('#studentStatus').value='active';R.loadStudents()});
$$('[data-action="addStudent"]').forEach(b=>b.onclick=()=>R.studentForm());
$$('[data-action="addStaff"]').forEach(b=>b.onclick=()=>R.staffForm());
$('#showArchivedStudents').onclick=()=>{view('students');$('#studentStatus').value='archived';R.loadStudents()};
$('#studentFind').onclick=R.loadStudents;$('#staffFind').onclick=R.loadStaff;$('#accessFind').onclick=window.WTSAccess.load;
$('#studentClass').onchange=R.loadStudents;$('#studentStatus').onchange=R.loadStudents;$('#staffStatus').onchange=R.loadStaff;
$('#refresh').onclick=()=>R.loadContext().then(()=>state.views[state.currentView]?.()).catch(e=>{toast(e.message,'error');if(/AUTH|PERMISSION|login/i.test(e.message))signOut()});
$('#login').onclick=signOut;
$('#gateForm').onsubmit=e=>{e.preventDefault();$('#authError').textContent='Connecting…';sessionStorage.setItem(W.STORE,JSON.stringify({code:$('#adminCode').value.trim(),secret:$('#adminSecret').value}));R.loadContext().then(()=>{$('#authError').textContent='';toast('Central Registry opened.','success')}).catch(err=>{sessionStorage.removeItem(W.STORE);W.connected(false,err.message);$('#adminSecret').value=''})};
$('#recordForm').onsubmit=async e=>{e.preventDefault();if(!state.handler)return;$('#saveRecord').disabled=true;try{await state.handler(e.currentTarget);$('#formDialog').close()}catch(err){toast(err.message,'error')}finally{$('#saveRecord').disabled=false}};
W.connected(false);try{const a=auth();$('#adminCode').value=a.code;R.loadContext().catch(()=>signOut())}catch{$('#adminCode').focus()}
for(const src of ['/identity-login.js','/identity-admin.js']){const script=document.createElement('script');script.src=src;script.async=true;document.head.appendChild(script)}
})();