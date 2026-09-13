# Explainable IDOR Analyzer

OpenAPI 파일 또는 URL을 입력하고, 선택적으로 소스 코드 ZIP과 이벤트 로그를 추가하여 설명 가능한 BOLA/IDOR 후보를 생성하는 독립형 웹 애플리케이션입니다.

## 분석 방식

1. **1차 정적 분석**: OpenAPI 파라미터 이름·타입·인증·경로를 이용해 Resource ID와 공격 후보를 찾습니다.
2. **2차 흐름 분석**: 이벤트 로그가 없으면 OpenAPI links 기반 흐름 추정으로 표시합니다. 이벤트 로그와 Links2CPN 저장소를 함께 제공하면 Links2CPN replay를 실행합니다.
3. **설명 생성**: 엔드포인트, 이유, 2차 상태, 수동 권한 검증 절차를 한국어로 보여줍니다.

> 이 도구는 실제 권한 우회까지 자동 확정하지 않습니다. 승인된 테스트 계정 A/B로 소유권 검증을 별도로 수행해야 합니다.

## 실행

Windows CMD:

```cmd
py -3.12 -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

브라우저에서 `http://127.0.0.1:8000`을 엽니다.

## 입력

- OpenAPI YAML/JSON 파일 또는 URL: 필수
- 소스 코드 ZIP: 선택. 현재 버전은 업로드를 안전하게 보관하는 입력 슬롯이며, 임의 코드를 실행하지 않습니다.
- 이벤트 로그: 선택
- Links2CPN 저장소 경로: 이벤트 로그를 재생할 때 선택

이벤트 로그가 없으면 `flow-inferred`로 표시되고 실제 replay는 하지 않습니다.

## 보안

허가받은 대상만 분석하십시오. URL 기능은 신뢰된 OpenAPI URL에만 사용하고, 운영 환경에서는 SSRF 차단·파일 크기 제한·인증·작업 격리가 필요합니다. 업로드된 소스 코드는 실행하지 않습니다.
