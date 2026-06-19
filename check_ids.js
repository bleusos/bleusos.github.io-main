const fs=require('fs');
const s=fs.readFileSync('buildamalwareworkshop.html','utf8');
const wanted=[
'cred-kerberoasting','cred-as-rep-roasting','cred-sam-dump','cred-ntds-dit','cred-browser-cookies-theft','cred-wifi-passwords','cred-ssh-key-theft','cred-gcp-service-account','cred-mimikatz-style','cred-passwd-file','cred-cloud-metadata',
'pri-kernel-exploit','pri-dll-search-order','pri-unquoted-service-path','pri-modifiable-service','pri-weak-folder-permissions','pri-token-impersonation','pri-named-pipe-impersonation','pri-scheduled-task-priv','pri-uac-environment-variable','pri-wmi-event-sub','pri-suid-linux'
];
const ids=[...s.matchAll(/id:\s*'([^']+)'/g)].map(m=>m[1]);
const present=wanted.filter(id=>ids.includes(id));
const missing=wanted.filter(id=>!ids.includes(id));
console.log('PRESENT_COUNT',present.length);
present.forEach(p=>console.log(p));
console.log('MISSING_COUNT',missing.length);
missing.forEach(m=>console.log(m));
console.log('TOTAL_IDS_IN_FILE',ids.length);
