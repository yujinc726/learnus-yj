from __future__ import annotations

import uuid
from typing import Dict, List, Optional, Tuple
import re
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from learnus_client import LearnUsClient, LearnUsLoginError

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:  # Fallback for older versions
    from backports.zoneinfo import ZoneInfo  # type: ignore

KST = ZoneInfo("Asia/Seoul")

app = FastAPI(title="LearnUs Alimi API")

# In-memory session store {token: LearnUsClient}
_SESSIONS: Dict[str, LearnUsClient] = {}

# Course cache {client_id: {course_id: (last_access_time, activities)}}
_COURSE_CACHE: Dict[int, Dict[int, Tuple[float, List]]] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str


# -------------------------------- Utils ---------------------------------

def get_client(x_auth_token: Optional[str] = Header(None)) -> LearnUsClient:
    if not x_auth_token or x_auth_token not in _SESSIONS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing token")
    return _SESSIONS[x_auth_token]


def _get_course_activities_cached(client: LearnUsClient, course_id: int, ttl: int = 900):
    """Return activities from cache if still fresh; otherwise fetch and update cache."""
    import time

    cache = _COURSE_CACHE.setdefault(id(client), {})
    if course_id in cache and time.time() - cache[course_id][0] < ttl:
        return cache[course_id][1]

    activities = client.get_course_activities(course_id)
    cache[course_id] = (time.time(), activities)
    return activities


# -------------------------------- Routes --------------------------------

@app.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    client = LearnUsClient()
    try:
        client.login(payload.username, payload.password)
    except LearnUsLoginError:
        raise HTTPException(status_code=400, detail="로그인에 실패했습니다. 학번/비밀번호를 확인해주세요.")
    except Exception:
        raise HTTPException(status_code=400, detail="로그인 중 알 수 없는 오류가 발생했습니다.")
    token = uuid.uuid4().hex
    _SESSIONS[token] = client
    return {"token": token}


@app.get("/courses")
def get_courses(client: LearnUsClient = Depends(get_client)):
    return client.get_courses()


@app.get("/events")
def get_events(course_id: Optional[int] = None, client: LearnUsClient = Depends(get_client)):
    """Return events aggregated across all courses unless `course_id` is provided."""

    # Current time in KST for deadline comparison
    now_kst = datetime.now(KST)

    # Determine course set
    if course_id is None:
        course_ids = [c["id"] for c in client.get_courses()]
    else:
        course_ids = [course_id]

    calendar_events: List[dict] = []
    todo_videos: List[dict] = []
    todo_assigns: List[dict] = []
    todo_quizzes: List[dict] = []

    # Map course id to name for prefixing titles
    course_name_map = {
        c["id"]: re.sub(r"\s*\([^)]*\)$", "", c["name"])
        for c in client.get_courses()
    }

    # Parallel fetch of course activities with simple ThreadPoolExecutor
    def fetch(cid):
        return cid, _get_course_activities_cached(client, cid)

    activities_by_course: Dict[int, List] = {}
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(16, len(course_ids))) as pool:
        for cid, acts in pool.map(fetch, course_ids):
            activities_by_course[cid] = acts

    # Collect assignments that require detail fetch
    assign_need_detail: List[Tuple[int, int, object]] = []  # (course_id, module_id, activity_ref)

    for cid in course_ids:
        activities = activities_by_course[cid]

        for a in activities:
            if a.type == "assign":
                # Skip if already completed
                if a.completed:
                    continue
                # If due_time already known, we may not need detail fetch
                if a.due_time is None:
                    assign_need_detail.append((cid, a.id, a))
            # nothing else yet

    # Fetch assignment details in parallel
    def fetch_assign(module_id):
        return module_id, client.get_assignment_detail(module_id)

    if assign_need_detail:
        with ThreadPoolExecutor(max_workers=min(16, len(assign_need_detail))) as pool:
            for module_id, detail in pool.map(lambda t: fetch_assign(t[1]), assign_need_detail):
                # find corresponding activity object
                for cid, mid, act in assign_need_detail:
                    if mid == module_id:
                        act.extra.update(detail)
                        if detail.get("due_time") and act.due_time is None:
                            act.due_time = detail["due_time"]
                        break

    # Now build lists
    for cid in course_ids:
        activities = activities_by_course[cid]

        for a in activities:
            full_title = f"[{course_name_map.get(cid, '')}] {a.title}"

            if a.type == "assign":
                # Re-evaluate after details
                if a.completed or a.extra.get("submitted"):
                    continue
                if not a.due_time:
                    continue
                # Skip past deadline
                if a.due_time < now_kst:
                    continue
                todo_assigns.append({"id": a.id, "title": full_title, "due": a.due_time.isoformat()})
            elif a.type == "vod":
                if a.completed or not a.due_time:
                    continue
                if a.due_time < now_kst:
                    continue
                todo_videos.append({"id": a.id, "title": full_title, "due": a.due_time.isoformat()})
            elif a.type == "quiz":
                if a.completed:
                    continue
                # 퀴즈는 마감일이 없을 수 있으므로 due_time이 없어도 표시
                if a.due_time and a.due_time < now_kst:
                    continue
                quiz_data = {"id": a.id, "title": full_title}
                if a.due_time:
                    quiz_data["due"] = a.due_time.isoformat()
                todo_quizzes.append(quiz_data)

            if a.due_time:
                calendar_events.append({
                    "id": a.id,
                    "title": full_title,
                    "type": a.type,
                    "completed": a.completed,
                    "start": a.due_time.isoformat(),
                    "allDay": True,
                })

    # Sort
    calendar_events.sort(key=lambda x: x["start"])
    todo_videos.sort(key=lambda x: x["due"])
    todo_assigns.sort(key=lambda x: x["due"])
    # 퀴즈는 due가 없을 수 있으므로 안전하게 정렬
    todo_quizzes.sort(key=lambda x: x.get("due", "9999-12-31"))

    return {"calendar": calendar_events, "videos": todo_videos, "assignments": todo_assigns, "quizzes": todo_quizzes}


# Simple health/token validation endpoint
@app.get("/ping")
def ping(client: LearnUsClient = Depends(get_client)):
    return {"ok": True}


# Logout: remove session & cache
@app.post("/logout")
def logout(x_auth_token: Optional[str] = Header(None)):
    if not x_auth_token or x_auth_token not in _SESSIONS:
        raise HTTPException(status_code=401, detail="Invalid token")
    client = _SESSIONS.pop(x_auth_token)
    _COURSE_CACHE.pop(id(client), None)
    return {"ok": True}


# ----------------------------- Static files -----------------------------
# Serve simple frontend (static/index.html etc.) under /
import pathlib
_static_path = pathlib.Path(__file__).parent / "static"
app.mount("/", StaticFiles(directory=_static_path, html=True), name="static") 