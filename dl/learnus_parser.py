from __future__ import annotations

import re
import datetime as dt
from dataclasses import dataclass, field
from typing import List, Optional

from bs4 import BeautifulSoup

__all__ = [
    "Activity",
    "parse_course_activities",
    "parse_assignment_detail",
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
_LATE_RE = re.compile(r"Late\s*:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

# Accept both 'YYYY-MM-DD HH:MM:SS' and 'YYYY-MM-DD HH:MM'
_DATETIME_PATTERNS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
]

def _parse_datetime(ts: str) -> dt.datetime:
    for fmt in _DATETIME_PATTERNS:
        try:
            return dt.datetime.strptime(ts, fmt)
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

    # Iterate in reverse to prefer activities appearing later (real week sections),
    # skipping early duplicates from the "이번 주" shortcut section at the top.
    for li in reversed(soup.select("li.activity")):
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
        if modtype not in {"vod", "assign"}:
            continue  # skip unsupported types for now

        # Title inside span.instancename (without nested span.accesshide)
        span_name = li.select_one("span.instancename")
        if not span_name:
            continue
        # Clone the span and remove any child with class accesshide
        title = span_name.get_text(strip=True)
        # Remove trailing '동영상' or '과제' word that came from accesshide span.
        title = re.sub(r"\s*(동영상|과제)$", "", title)

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
            late_m = _LATE_RE.search(text)
            if late_m:
                late_due_time = _parse_datetime(late_m.group(1))

        # -------------------------------------------------------------
        # Availability: For VOD items, LearnUs renders an <a> tag with
        # an onclick="window.open(...)" when the video is still
        # viewable.  Once the viewing window is over, that anchor is
        # replaced by a <div class="dimmed dimmed_text"> and thus the
        # <a> tag is missing.  We use presence of the anchor as a
        # heuristic for whether the video is still playable.
        # -------------------------------------------------------------
        playable = bool(li.select_one("div.activityinstance a"))

        activities.append(
            Activity(
                id=module_id,
                type=modtype,
                title=title,
                completed=completed,
                open_time=open_time,
                due_time=due_time,
                late_due_time=late_due_time,
                extra={"playable": playable},
            )
        )

    return list(reversed(activities))


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
            info["submitted"] = "완료" in value  # crude heuristic
        elif label == "채점 상황":
            info["grading_status"] = value
        elif label == "종료 일시":
            try:
                info["due_time"] = _parse_datetime(value)
            except ValueError:
                pass

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
            continue  # skip placeholder '강좌를 선택하세요.' etc.
        courses.append({"id": int(value), "name": opt.get_text(strip=True)})
    return courses 