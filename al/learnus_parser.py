from __future__ import annotations

import re
import datetime as dt
from dataclasses import dataclass, field
from typing import List, Optional
from bs4 import BeautifulSoup
from zoneinfo import ZoneInfo

__all__ = [
    "Activity",
    "parse_course_activities",
    "parse_assignment_detail",
    "parse_quiz_detail",
    "parse_dashboard_courses",
]


@dataclass
class Activity:
    id: int
    type: str  # e.g. 'vod', 'assign'
    title: str
    completed: bool
    # For items where a date range is available (e.g. vod), we record both
    open_time: Optional[dt.datetime] = None
    due_time: Optional[dt.datetime] = None
    late_due_time: Optional[dt.datetime] = None
    extra: dict = field(default_factory=dict)


_DATE_RANGE_RE = re.compile(
    r"\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*~\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
)
_ONLY_END_DATE_RE = re.compile(
    r"\s*~\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
)
_LATE_RE = re.compile(r"Late\s*:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

# Accept both 'YYYY-MM-DD HH:MM:SS' and 'YYYY-MM-DD HH:MM'
_DATETIME_PATTERNS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
]
# Korea Standard Time
KST = ZoneInfo("Asia/Seoul")

def _parse_datetime(ts: str) -> dt.datetime:
    for fmt in _DATETIME_PATTERNS:
        try:
            return dt.datetime.strptime(ts, fmt).replace(tzinfo=KST)
        except ValueError:
            continue
    raise ValueError(f"Unrecognised datetime format: {ts}")


def parse_course_activities(html: str) -> List[Activity]:
    """Parse LearnUs course page HTML and return list of Activity objects.

    Supports 'vod' (동영상) and 'assign' (과제) modules. Others are ignored for now.
    """
    soup = BeautifulSoup(html, "html.parser")
    activities: list[Activity] = []
    seen_ids: set[int] = set()

    for li in soup.select("li.activity"):
        classes = li.get("class", [])
        # Identify module ID
        module_id_str = li.get("id", "module-0").replace("module-", "")
        try:
            module_id = int(module_id_str)
        except ValueError:
            continue

        if module_id in seen_ids:
            continue  # skip duplicates (e.g., current week appearing twice)
        seen_ids.add(module_id)

        # Determine type based on classes like 'modtype_vod', 'modtype_assign'
        modtype = None
        for cls in classes:
            if cls.startswith("modtype_"):
                modtype = cls.replace("modtype_", "")
                break
        if modtype not in {"vod", "assign", "quiz"}:
            continue  # skip unsupported types for now

        # Title inside span.instancename (without nested span.accesshide)
        span_name = li.select_one("span.instancename")
        if not span_name:
            continue
        
        # Remove any child with class accesshide
        accesshide = span_name.select_one("span.accesshide")
        if accesshide:
            accesshide.decompose()
        title = span_name.get_text(strip=True)
        # Remove trailing '동영상' or '과제' word that came from accesshide span
        # title = re.sub(r"\s*(동영상|과제)$", "", title)

        # Completion status: check for <img ... src="...completion-auto-y.svg"> existing inside .autocompletion
        completed = False
        comp_img = li.select_one("span.autocompletion img")
        if comp_img and comp_img.has_attr("src"):
            if "completion-auto-y" in comp_img["src"]:
                completed = True

        open_time = None
        due_time = None
        late_due_time = None

        # Parse date range text if available (vod items have it)
        display_text = li.select_one("span.displayoptions")
        if display_text:
            text = display_text.get_text(" ", strip=True)
            m = _DATE_RANGE_RE.search(text)
            if m:
                open_time = _parse_datetime(m.group(1))
                due_time = _parse_datetime(m.group(2))
            else:
                # Check for end date only format (~ END_TIME)
                end_only_m = _ONLY_END_DATE_RE.search(text)
                if end_only_m:
                    open_time = None
                    due_time = _parse_datetime(end_only_m.group(1))
            late_m = _LATE_RE.search(text)
            if late_m:
                late_due_time = _parse_datetime(late_m.group(1))

        activities.append(
            Activity(
                id=module_id,
                type=modtype,
                title=title,
                completed=completed,
                open_time=open_time,
                due_time=due_time,
                late_due_time=late_due_time,
            )
        )

    return activities


def parse_assignment_detail(html: str) -> dict:
    """Parse LearnUs assignment detail page and extract submission + due info.

    Returns
    -------
    dict with keys:
        submitted : bool | None
        submission_status : str | None
        grading_status : str | None
        due_time : datetime | None
    """
    soup = BeautifulSoup(html, "html.parser")
    info = {
        "submitted": None,
        "submission_status": None,
        "grading_status": None,
        "due_time": None,
    }

    for tr in soup.select("tr"):
        label_td = tr.select_one("td.cell.c0")
        value_td = tr.select_one("td.cell.c1")
        if not label_td or not value_td:
            continue
        label = label_td.get_text(strip=True)
        value = value_td.get_text(strip=True)
        if label == "제출 여부":
            info["submission_status"] = value
            info["submitted"] = value == "제출 완료"
        elif label == "Submission status":
            info["submission_status"] = value
            info["submitted"] = value == "Submitted for grading"
        elif label == "채점 상황" or label == "Grading status":
            info["grading_status"] = value
        elif label == "종료 일시" or label == "Due date":
            try:
                info["due_time"] = _parse_datetime(value)
            except ValueError:
                pass

    return info


def parse_quiz_detail(html: str) -> dict:
    """Parse LearnUs quiz detail page and extract due time info.

    Returns
    -------
    dict with keys:
        due_time : datetime | None
    """
    soup = BeautifulSoup(html, "html.parser")
    info = {
        "due_time": None,
    }

    # Look for due time patterns in both Korean and English
    # Common patterns: "종료일시 : YYYY-MM-DD HH:MM", "Due date : YYYY-MM-DD HH:MM", etc.
    due_time_keywords = [
        "종료일시",      # Korean: End time
        "마감일시",      # Korean: Due time
        "Due date",     # English
        "End time",     # English
        "Closing time", # English
        "Close date",   # English
        "Deadline",     # English
    ]
    
    for p in soup.find_all("p"):
        text = p.get_text(strip=True)
        for keyword in due_time_keywords:
            if keyword in text and ":" in text:
                # Extract the datetime part after the first ":"
                parts = text.split(":", 1)
                if len(parts) >= 2:
                    date_str = parts[1].strip()
                    try:
                        # Parse "2025-09-27 23:59" format
                        info["due_time"] = _parse_datetime(date_str + ":00")  # Add seconds
                        break
                    except ValueError:
                        # Try without adding seconds in case it's already full format
                        try:
                            info["due_time"] = _parse_datetime(date_str)
                            break
                        except ValueError:
                            continue
        if info["due_time"]:  # If we found a valid due_time, stop looking
            break

    return info


def parse_dashboard_courses(html: str) -> List[dict]:
    """Parse main dashboard page and return list of courses with `id`, `name`."""
    soup = BeautifulSoup(html, "html.parser")
    courses = []
    select = soup.select_one("select.form-control-my-activity-course")
    if not select:
        return courses
    for opt in select.find_all("option"):
        value = opt.get("value", "").strip()
        if not value.isdigit():
            continue
        courses.append({"id": int(value), "name": opt.get_text(strip=True)})
    return courses 