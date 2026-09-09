const el=id=>document.getElementById(id);
const number=v=>typeof v==='string'&&v.startsWith('0x')?parseInt(v,16):v;
const short=v=>v?`${v.slice(0,12)}…${v.slice(-8)}`:'—';
function row(target,values){const tr=document.createElement('tr');for(const value of values){const td=document.createElement('td');if(value instanceof Node)td.append(value);else td.textContent=String(value??'—');tr.append(td)}target.append(tr)}
function address(v){const span=document.createElement('span');span.textContent=short(v);span.title=v||'';span.className='mono';return span}
async function refresh(){try{
 const response=await fetch('/api/status',{cache:'no-store'});if(!response.ok)throw Error('관측 서버 응답 오류');const data=await response.json();
 const nodes=data.nodes||[];const first=nodes.find(n=>n.node===1);const live=nodes.filter(n=>!n.error&&Date.now()-new Date(n.time)<20000);
 el('experiment').textContent=`초기 등록 ${data.bootstrapCount}노드 + 후발 ${nodes.length-data.bootstrapCount}노드 · 실제 GCP vTPM · Chain ${data.chainId}`;
 el('policy').textContent=`활성화 대기 ${data.activationDelay}블록 · 생산 슬롯 ${data.producerSlots}개 중 ${data.producerThreshold}개 승인 · 슬롯은 독립된 사람 수가 아닙니다.`;
 el('online').textContent=`${live.length} / ${nodes.length}`;el('height').textContent=first&&!first.error?first.height.toLocaleString():'—';
 el('active').textContent=first&&!first.error?`${(first.registrations||[]).filter(r=>r.active).length} / ${nodes.length}`:'—';
 const hashes=new Set(live.map(n=>`${n.height}:${n.hash}`));
 el('notice').textContent=live.length<nodes.length?'일부 노드가 준비 중이거나 응답하지 않습니다. 아래 관측 시각을 확인하세요.':hashes.size===1?`${nodes.length}개 노드의 관측 높이와 블록 해시가 일치합니다.`:'노드별 높이 또는 해시가 다릅니다. 전파 중일 수 있으므로 다음 갱신을 확인하세요.';
 for(const id of ['nodes','registrations','blocks'])el(id).replaceChildren();
 for(const n of nodes)row(el('nodes'),[`Node ${n.node}`,n.error?'오류':n.height,n.error?'—':n.peers,n.error?n.error:n.mining?'실행 중':'꺼짐',address(n.hash),n.time?new Date(n.time).toLocaleTimeString():'—']);
 for(const [i,r]of (first?.registrations||[]).entries())row(el('registrations'),[`Node ${i+1}`,r.bootstrap?'제네시스':'동적 등록',r.active?'활성':r.registered?'활성화 대기':'미등록',address(r.controller),address(r.did)]);
 for(const b of first?.blocks||[]){const button=document.createElement('button');button.textContent=number(b.number);button.addEventListener('click',()=>{el('block-json').textContent=JSON.stringify(b,null,2);el('detail').open=true;el('detail').scrollIntoView({behavior:'smooth',block:'nearest'})});row(el('blocks'),[button,new Date(number(b.timestamp)*1000).toLocaleString(),address(b.miner),number(b.difficulty),number(b.eligibilityThreshold)??'—',b.transactions?.length??0])}
}catch(error){el('notice').textContent=`갱신 실패: ${error.message}. 마지막 표시 자료는 최신 상태가 아닐 수 있습니다.`}}
refresh();setInterval(refresh,5000);
