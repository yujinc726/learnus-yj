from __future__ import annotations

import uuid
from typing import Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Depends, Header, status, UploadFile, File, Query, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from learnus_client import LearnUsClient, LearnUsLoginError
from session_utils import issue_token, fastapi_get_client, get_learnus_client, verify_token

app = FastAPI(title="LearnUs Downloader API")

# Course cache {client_id: {course_id: (last_access_time, activities)}}
_COURSE_CACHE: Dict[int, Dict[int, Tuple[float, List]]] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str


# ------------------------------- Guest Auth ---------------------------------

class GuestLoginResponse(BaseModel):
    token: str


# Endpoint for anonymous users to obtain a short-lived session token that can be
# used for guest-only operations (such as HTML-based video download).  This
# mirrors the standard /login endpoint but skips credential verification and
# does NOT attach a LearnUsClient instance to the session store.

@app.post("/guest_login", response_model=GuestLoginResponse, summary="비회원 로그인")
def guest_login():
    """Issue *guest* token.  Guest sessions do **not** carry credentials."""
    token = issue_token("guest", "", guest=True)
    return {"token": token}


# -------------------------------- Utils ---------------------------------

# FastAPI dependency that returns a logged-in client (or raises 401)
get_client = fastapi_get_client()


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
    """Authenticate against LearnUs and return a *signed* session token."""
    client = LearnUsClient()
    try:
        client.login(payload.username, payload.password)
    except LearnUsLoginError:
        raise HTTPException(status_code=400, detail="로그인에 실패했습니다. 학번/비밀번호를 확인해주세요.")
    except Exception:
        raise HTTPException(status_code=400, detail="로그인 중 알 수 없는 오류가 발생했습니다.")

    # Successful – issue stateless token and cache client locally for performance
    token = issue_token(payload.username, payload.password)
    from session_utils import _CLIENT_CACHE  # type: ignore
    _CLIENT_CACHE[token] = client  # cache within *this* worker
    return {"token": token}


@app.get("/courses")
def get_courses(client: LearnUsClient = Depends(get_client)):
    return client.get_courses()


# Simple health/token validation endpoint
@app.get("/ping")
def ping(client: LearnUsClient = Depends(get_client)):
    return {"ok": True}


# Logout: remove session & cache
@app.post("/logout")
def logout(x_auth_token: Optional[str] = Header(None)):
    """Invalidate local cache for the supplied token."""
    if not x_auth_token:
        raise HTTPException(status_code=401, detail="Invalid token")
    from session_utils import _CLIENT_CACHE  # type: ignore
    client = _CLIENT_CACHE.pop(x_auth_token, None)
    if client is not None:
        _COURSE_CACHE.pop(id(client), None)
    return {"ok": True}


# ----------------------------- Static files -----------------------------
# Serve simple frontend (static/index.html etc.) under /
import pathlib


# (mount is added *after* all API routes to ensure they take lower precedence)

# -------------------------------- New Video Endpoints --------------------------------

import subprocess, tempfile
import shlex
from urllib.parse import quote
import shutil, os

@app.get("/videos")
def list_videos(course_id: int, client: LearnUsClient = Depends(get_client)):
    """Return list of VOD (video) activities for the given course."""
    activities = _get_course_activities_cached(client, course_id)
    videos = [
        {
            "id": a.id,
            "title": a.title,
            "completed": a.completed,
            "open": a.open_time.isoformat() if a.open_time else None,
            "due": a.due_time.isoformat() if a.due_time else None,
            "available": a.extra.get("playable", True),
        }
        for a in activities
        if a.type == "vod"
    ]
    return {"videos": videos}


@app.get("/download/{video_id}.{ext}")
def download_video(video_id: int, ext: str, client: LearnUsClient = Depends(get_client)):
    """Stream MP4/MP3 conversion of the given video module to the user.

    ext must be "mp4" or "mp3".
    """
    if ext not in {"mp4", "mp3"}:
        raise HTTPException(status_code=400, detail="Unsupported extension. Use mp4 or mp3.")

    video_page_url = f"{client.BASE_URL}/mod/vod/viewer.php?id={video_id}"
    try:
        title, m3u8_url = client.get_video_stream_info(video_page_url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Probe duration (in seconds) using ffprobe, if available
    ffprobe_bin = os.getenv("FFPROBE_PATH") or shutil.which("ffprobe") or shutil.which("ffprobe.exe")
    stream_duration: Optional[float] = None
    stream_bitrate: Optional[int] = None  # bits per second
    if ffprobe_bin:
        try:
            probe_cmd = [
                ffprobe_bin,
                "-v", "error",
                "-show_entries", "format=duration,bit_rate",
                "-of", "default=noprint_wrappers=1:nokey=1",
                m3u8_url,
            ]
            result = subprocess.run(probe_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                if lines:
                    try:
                        stream_duration = float(lines[0])
                    except ValueError:
                        pass
                    if len(lines) > 1:
                        try:
                            stream_bitrate = int(lines[1])  # bits/sec
                        except ValueError:
                            pass
        except Exception:
            # ignore probe errors
            stream_duration = None
            stream_bitrate = None

    # Prepare ffmpeg command
    ffmpeg_bin = os.getenv("FFMPEG_PATH") or shutil.which("ffmpeg") or shutil.which("ffmpeg.exe")
    if not ffmpeg_bin:
        raise HTTPException(status_code=500, detail="ffmpeg executable not found on server. Install ffmpeg and ensure it is in PATH.")

    filename = f"{title}.{ext}"
    headers = {"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"}
    if stream_duration:
        headers["X-Stream-Duration"] = str(stream_duration)
    if stream_bitrate:
        headers["X-Stream-Bitrate"] = str(stream_bitrate)

    if ext == "mp4":
        # ------------------------------------------------------------------
        # For MP4 we first remux into a temporary file so that ffmpeg can write
        # a proper, self-contained MP4 (moov atom relocated with +faststart).
        # Writing directly to a pipe is not possible because the MP4 muxer
        # requires a seekable output when not using fragmented mode.
        # ------------------------------------------------------------------
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as tmp:
            tmp_path = tmp.name

        remux_cmd = [
            ffmpeg_bin,
            "-loglevel", "error",
            "-y",
            "-i", m3u8_url,
            "-c", "copy",
            "-bsf:a", "aac_adtstoasc",
            "-movflags", "+faststart",
            tmp_path,
        ]

        result = subprocess.run(remux_cmd, capture_output=True)
        if result.returncode != 0:
            # Clean up temp file on error
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            raise HTTPException(status_code=500, detail="ffmpeg failed to remux video")

        # Use BackgroundTasks to delete the temporary file after the response is sent
        def _cleanup():
            try:
                os.remove(tmp_path)
            except Exception:
                pass

        background_tasks = BackgroundTasks()
        background_tasks.add_task(_cleanup)

        return FileResponse(tmp_path, media_type="video/mp4", filename=filename, headers=headers, background=background_tasks)

    # -------------------------------- MP3 (streaming) -------------------------------
    codec_args = "-vn -c:a libmp3lame -b:a 192k -f mp3"
    cmd = f"{shlex.quote(ffmpeg_bin)} -loglevel error -y -i {shlex.quote(m3u8_url)} {codec_args} pipe:1"

    process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.stdout is None:
        raise HTTPException(status_code=500, detail="Failed to initiate ffmpeg stream")

    def iterfile():
        try:
            while True:
                chunk = process.stdout.read(1024 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            process.stdout.close()
            process.kill()

    return StreamingResponse(iterfile(), media_type="audio/mpeg", headers=headers)


# --------------------------- Guest download via HTML ---------------------------

@app.post("/guest/download")
async def guest_download(
    ext: str = Query(..., regex="^(mp4|mp3)$", description="Download type: mp4 or mp3"),
    file: UploadFile = File(..., description="HTML page containing .m3u8 URL"),
    x_auth_token: Optional[str] = Header(None),
):
    """Accept an HTML file uploaded by a guest user, extract the first m3u8 URL and
    convert/stream it as MP4 or MP3 to the client.

    The caller must include the token obtained from /guest_login in the
    X-Auth-Token header.  The session associated with that token must be a guest
    session (i.e. value is None).
    """

    # Basic token validation (guest only) – stateless
    if not x_auth_token:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    payload = verify_token(x_auth_token)
    if not payload.get("guest"):
        raise HTTPException(status_code=400, detail="Not a guest session")

    # Read uploaded HTML
    try:
        raw = await file.read()
        html_text = raw.decode("utf-8", errors="ignore")
    except Exception:
        raise HTTPException(status_code=400, detail="파일을 읽는 중 오류가 발생했습니다.")

    # ------------------------------------------------------------------
    # Parse HTML to obtain m3u8 URL & title (mirror get_video_stream_info)
    # ------------------------------------------------------------------
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html_text, "html.parser")

    # Find m3u8 source tag
    source_tag = soup.find("source", {"type": "application/x-mpegURL"})
    if source_tag is None or not source_tag.get("src"):
        raise HTTPException(status_code=400, detail="HTML 내에서 m3u8 <source> 태그를 찾을 수 없습니다.")

    m3u8_url: str = source_tag["src"]

    # Extract and sanitise title
    title = file.filename.rsplit(".", 1)[0]
    header_div = soup.find("div", id="vod_header")
    if header_div is not None and header_div.find("h1") is not None:
        h1 = header_div.find("h1")
        for span in h1.find_all("span"):
            span.decompose()
        extracted = h1.get_text(strip=True)
        if extracted:
            invalid_chars = "\\/:*?\"<>|"
            title = extracted.translate(str.maketrans(invalid_chars, '＼／：＊？＂＜＞｜'))

    # Probe duration/bitrate using ffprobe if available (reuse logic above)
    ffprobe_bin = os.getenv("FFPROBE_PATH") or shutil.which("ffprobe") or shutil.which("ffprobe.exe")
    stream_duration: Optional[float] = None
    stream_bitrate: Optional[int] = None
    if ffprobe_bin:
        try:
            probe_cmd = [
                ffprobe_bin,
                "-v", "error",
                "-show_entries", "format=duration,bit_rate",
                "-of", "default=noprint_wrappers=1:nokey=1",
                m3u8_url,
            ]
            result = subprocess.run(probe_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                if lines:
                    try:
                        stream_duration = float(lines[0])
                    except ValueError:
                        pass
                    if len(lines) > 1:
                        try:
                            stream_bitrate = int(lines[1])
                        except ValueError:
                            pass
        except Exception:
            stream_duration = None
            stream_bitrate = None

    # ffmpeg command (same as /download)
    ffmpeg_bin = os.getenv("FFMPEG_PATH") or shutil.which("ffmpeg") or shutil.which("ffmpeg.exe")
    if not ffmpeg_bin:
        raise HTTPException(status_code=500, detail="ffmpeg executable not found on server. Install ffmpeg and ensure it is in PATH.")

    filename = f"{title}.{ext}"
    headers = {"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"}
    if stream_duration:
        headers["X-Stream-Duration"] = str(stream_duration)
    if stream_bitrate:
        headers["X-Stream-Bitrate"] = str(stream_bitrate)

    if ext == "mp4":
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as tmp:
            tmp_path = tmp.name

        remux_cmd = [
            ffmpeg_bin,
            "-loglevel", "error",
            "-y",
            "-i", m3u8_url,
            "-c", "copy",
            "-bsf:a", "aac_adtstoasc",
            "-movflags", "+faststart",
            tmp_path,
        ]

        result = subprocess.run(remux_cmd, capture_output=True)
        if result.returncode != 0:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            raise HTTPException(status_code=500, detail="ffmpeg failed to remux video")

        def _cleanup():
            try:
                os.remove(tmp_path)
            except Exception:
                pass

        background_tasks = BackgroundTasks()
        background_tasks.add_task(_cleanup)

        return FileResponse(tmp_path, media_type="video/mp4", filename=filename, headers=headers, background=background_tasks)

    codec_args = "-vn -c:a libmp3lame -b:a 192k -f mp3"
    cmd = f"{shlex.quote(ffmpeg_bin)} -loglevel error -y -i {shlex.quote(m3u8_url)} {codec_args} pipe:1"

    process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.stdout is None:
        raise HTTPException(status_code=500, detail="Failed to initiate ffmpeg stream")

    def iterfile():
        try:
            while True:
                chunk = process.stdout.read(1024 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            process.stdout.close()
            process.kill()

    return StreamingResponse(iterfile(), media_type="audio/mpeg", headers=headers)


# ----------------------------- Static mount (last) -----------------------------
_static_path = pathlib.Path(__file__).parent / "static"
app.mount("/", StaticFiles(directory=_static_path, html=True), name="static") 