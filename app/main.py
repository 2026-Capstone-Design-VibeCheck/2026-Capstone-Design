from __future__ import annotations
import json, shutil, tempfile, zipfile
from pathlib import Path
from urllib.parse import urlparse
import requests, yaml
from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from .bola_idor_detector import OpenAPIResourceIDDetector, load_openapi_file
from .links2cpn_two_stage_detector import run_links2cpn
from .explain import build_report

BASE=Path(__file__).resolve().parent.parent
app=FastAPI(title='Explainable IDOR Analyzer')
app.mount('/static',StaticFiles(directory=BASE/'static'),name='static')

def read_spec(path:Path): return load_openapi_file(str(path))
def safe_url(u:str):
    p=urlparse(u)
    if p.scheme not in ('http','https') or not p.netloc: raise HTTPException(400,'유효한 http/https URL이 아닙니다.')

def save_upload(upload:UploadFile, dest:Path):
    with dest.open('wb') as f: shutil.copyfileobj(upload.file,f)

def locate_spec(root:Path):
    for p in root.rglob('*'):
        if p.is_file() and p.suffix.lower() in ('.yaml','.yml','.json'):
            try:
                d=read_spec(p)
                if isinstance(d,dict) and 'paths' in d: return p
            except Exception: pass
    return None

def stage1(spec):
    # Apply global OpenAPI security when operation-level security is absent.
    if spec.get('security'):
        for item in spec.get('paths',{}).values():
            if isinstance(item,dict):
                for m,o in item.items():
                    if isinstance(o,dict) and m.lower() in OpenAPIResourceIDDetector.HTTP_METHODS and 'security' not in o: o['security']=spec['security']
    return OpenAPIResourceIDDetector(spec).analyze()

@app.get('/',response_class=HTMLResponse)
def home(): return (BASE/'static/index.html').read_text(encoding='utf-8')

@app.post('/api/analyze')
async def analyze(openapi:UploadFile|None=File(None), openapi_url:str|None=Form(None), source_zip:UploadFile|None=File(None), event_log:UploadFile|None=File(None), links2cpn_repo:str|None=Form(None)):
    if not openapi and not openapi_url: raise HTTPException(400,'OpenAPI 파일 또는 URL이 필요합니다.')
    work=Path(tempfile.mkdtemp(prefix='idor-'))
    try:
        spec_path=work/'openapi.yaml'
        if openapi:
            save_upload(openapi,spec_path)
        else:
            safe_url(openapi_url)
            r=requests.get(openapi_url,timeout=20); r.raise_for_status(); spec_path.write_bytes(r.content)
        spec=read_spec(spec_path); s1=stage1(spec)
        # Optional source archive is retained for future code-evidence analyzers; no execution.
        source_note='소스 코드가 제공되지 않음'
        if source_zip:
            src=work/'source.zip'; save_upload(source_zip,src)
            source_note='소스 ZIP 수신됨(코드 실행 없이 정적 분석 대상으로 보관)'
        s2={'success':False,'mode':'openapi-links-static','status':'flow-inferred','replay_events':[],'message':'이벤트 로그 없이 OpenAPI links 흐름만 분석했습니다.'}
        if event_log and links2cpn_repo:
            log=work/'events.log'; save_upload(event_log,log)
            s2=run_links2cpn(links2cpn_repo,str(spec_path),str(log),timeout=300)
        result={**s1,'links2cpn':s2,'source_note':source_note}
        return build_report(result)
    except HTTPException: raise
    except Exception as e: raise HTTPException(500,f'분석 실패: {type(e).__name__}: {e}')
    finally: shutil.rmtree(work,ignore_errors=True)
