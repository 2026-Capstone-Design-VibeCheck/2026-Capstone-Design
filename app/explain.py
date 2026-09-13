from typing import Any

def explain(f: dict[str, Any]) -> str:
    path=f.get('path','?'); method=f.get('method','?'); tech=f.get('technique','IDOR'); reason=f.get('reason','')
    flow=f.get('dynamic_status','not-replayed')
    if flow=='confirmed-flow': flow_text='실제 이벤트 흐름이 Links2CPN 모델과 일치했습니다.'
    elif flow=='flow-inferred': flow_text='이벤트 로그 없이 OpenAPI links에서 리소스 흐름을 추정했습니다.'
    else: flow_text='실제 호출 흐름은 확인되지 않았습니다.'
    return (f'{method} {path}는 {tech} 후보입니다. {reason} '
            f'{flow_text} 다만 이것은 권한 우회 자체의 확정이 아닙니다. '
            '사용자 A의 토큰으로 사용자 B 리소스 ID를 요청하는 승인된 테스트가 필요합니다.')

def build_report(result: dict[str,Any]) -> dict[str,Any]:
    fs=result.get('findings',[]); candidates=[f for f in fs if f.get('matched')]
    items=[]
    for f in candidates:
        x=dict(f); x['explanation']=explain(x); items.append(x)
    return {'summary':{'total_candidates':len(items),'flow_confirmed':sum(x.get('dynamic_status')=='confirmed-flow' for x in items),'authorization_verified':0},'findings':items,'disclaimer':'자동 분석 결과이며 실제 IDOR 확정에는 승인된 사용자 간 권한 검증이 필요합니다.'}
