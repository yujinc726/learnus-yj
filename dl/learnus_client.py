from __future__ import annotations

import logging
from typing import Tuple, Optional

import requests
from bs4 import BeautifulSoup
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

logger = logging.getLogger(__name__)


class LearnUsLoginError(Exception):
    """Raised when SSO login to LearnUs fails."""


class LearnUsClient:
    """Minimal LearnUs client that handles Yonsei SSO authentication.

    Notes
    -----
    The implementation is adapted from a working proof-of-concept snippet the
    user provided.  It bundles the rather involved *Pass-NI* / Yonsei SSO flow
    into a reusable class.
    """

    BASE_URL = "https://ys.learnus.org"
    _BASE_HEADERS = {"User-Agent": "Mozilla/5.0"}

    def __init__(self) -> None:
        self.session: Optional[requests.Session] = None

    # ---------------------------------------------------------------------
    # Public helpers
    # ---------------------------------------------------------------------
    def login(self, username: str, password: str) -> None:
        """Perform Yonsei SSO login using the *exact* flow that is known to work.

        This implementation is lifted verbatim (save for minor variable renames)
        from the user's original script to avoid subtle differences that were
        causing token-fetch failures.
        """
        import requests  # local import to be explicit

        session = requests.Session()
        base_headers = {"User-Agent": "Mozilla/5.0"}

        def post_request(url: str, headers: dict, data: dict):
            res = session.post(url, headers=headers, data=data)
            res.raise_for_status()
            return res

        def get_value_from_input(res_text: str, input_name: str):
            soup = BeautifulSoup(res_text, "html.parser")
            tag = soup.find("input", {"name": input_name})
            return tag["value"] if tag else None

        def get_multiple_values(res_text: str, names: list[str]):
            soup = BeautifulSoup(res_text, "html.parser")
            values = {}
            for n in names:
                tag = soup.find("input", {"name": n})
                if not tag:
                    return None
                values[n] = tag["value"]
            return values

        # 0) coursemosLogin – obtain S1
        headers = base_headers.copy()
        headers["Referer"] = f"{self.BASE_URL}/login/method/sso.php"
        data = {
            "ssoGubun": "Login",
            "logintype": "sso",
            "type": "popup_login",
            "username": username,
            "password": password,
        }
        res = post_request(f"{self.BASE_URL}/passni/sso/coursemosLogin.php", headers, data)
        s1 = get_value_from_input(res.text, "S1")
        if not s1:
            raise LearnUsLoginError("Failed to obtain S1 (step 0)")

        # 1) PmSSOService – obtain ssoChallenge & keyModulus
        headers["Referer"] = f"{self.BASE_URL}/"
        data.update({
            "app_id": "ednetYonsei",
            "retUrl": self.BASE_URL,
            "failUrl": f"{self.BASE_URL}/login/index.php",
            "baseUrl": self.BASE_URL,
            "S1": s1,
            "loginUrl": f"{self.BASE_URL}/passni/sso/coursemosLogin.php",
            "ssoGubun": "Login",
            "refererUrl": self.BASE_URL,
            "test": "SSOAuthLogin",
            "loginType": "invokeID",
            "E2": "",
        })
        res = post_request("https://infra.yonsei.ac.kr/sso/PmSSOService", headers, data)
        vals = get_multiple_values(res.text, ["ssoChallenge", "keyModulus"])
        if not vals:
            raise LearnUsLoginError("Failed to obtain ssoChallenge/keyModulus (step 1)")
        sc, km = vals["ssoChallenge"], vals["keyModulus"]

        # 2) coursemosLogin – send encrypted credentials, get new S1
        key_pair = RSA.construct((int(km, 16), 0x10001))
        cipher = PKCS1_v1_5.new(key_pair)
        payload = f'{{"userid":"{username}","userpw":"{password}","ssoChallenge":"{sc}"}}'
        e2 = cipher.encrypt(payload.encode()).hex()

        headers["Referer"] = "https://infra.yonsei.ac.kr/"
        data.update({
            "ssoChallenge": sc,
            "keyModulus": km,
            "keyExponent": "10001",
            "E2": e2,
        })
        res = post_request(f"{self.BASE_URL}/passni/sso/coursemosLogin.php", headers, data)
        s1 = get_value_from_input(res.text, "S1")
        if not s1:
            raise LearnUsLoginError("Failed to obtain S1 (step 2)")

        # 3) PmSSOAuthService – get E3/E4/S2/CLTID
        headers["Referer"] = f"{self.BASE_URL}/"
        data.update({"S1": s1})
        res = post_request("https://infra.yonsei.ac.kr/sso/PmSSOAuthService", headers, data)
        vals = get_multiple_values(res.text, ["E3", "E4", "S2", "CLTID"])
        if not vals:
            raise LearnUsLoginError("Failed to obtain E3/E4/S2/CLTID (step 3)")
        e3, e4, s2, cltid = vals["E3"], vals["E4"], vals["S2"], vals["CLTID"]

        # 4) spLoginData & spLoginProcess – finalise session
        headers["Referer"] = "https://infra.yonsei.ac.kr/"
        data = {
            "app_id": "ednetYonsei",
            "retUrl": self.BASE_URL,
            "failUrl": f"{self.BASE_URL}/login/index.php",
            "baseUrl": self.BASE_URL,
            "loginUrl": f"{self.BASE_URL}/passni/sso/coursemosLogin.php",
            "E3": e3,
            "E4": e4,
            "S2": s2,
            "CLTID": cltid,
            "ssoGubun": "Login",
            "refererUrl": self.BASE_URL,
            "test": "SSOAuthLogin",
            "username": username,
            "password": password,
        }
        post_request(f"{self.BASE_URL}/passni/sso/spLoginData.php", headers, data)
        session.get(f"{self.BASE_URL}/passni/spLoginProcess.php")

        # Success – store session
        self.session = session
        logger.info("[LearnUs] Authenticated as %s", username)

    def ensure_logged_in(self) -> requests.Session:
        if self.session is None:
            raise LearnUsLoginError("Client is not logged in. Call `login()` first.")
        return self.session

    def get_video_stream_info(self, video_page_url: str) -> Tuple[str, str]:
        """Return `(title, m3u8_url)` for a given LearnUs video page."""
        session = self.ensure_logged_in()
        res = session.get(video_page_url)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")

        # Extract m3u8 source URL
        source_tag = soup.find("source", {"type": "application/x-mpegURL"})
        if source_tag is None:
            raise LearnUsLoginError("Unable to locate video source tag (application/x-mpegURL)")
        m3u8_url: str = source_tag["src"]

        # Extract & sanitise video title (remove spans and invalid characters)
        header_div = soup.find("div", id="vod_header")
        if header_div is None or header_div.find("h1") is None:
            raise LearnUsLoginError("Unable to locate video title on the page")
        h1 = header_div.find("h1")
        for span in h1.find_all("span"):
            span.decompose()
        title: str = h1.get_text(strip=True)
        invalid_chars = '\\/:*?"<>|'
        title = title.translate(str.maketrans(invalid_chars, "＼／：＊？＂＜＞｜"))

        return title, m3u8_url

    def get_course_activities(self, course_id: int):
        """Fetch course page HTML and parse activities list using learnus_parser."""
        from learnus_parser import parse_course_activities  # local import to avoid circular

        session = self.ensure_logged_in()
        url = f"{self.BASE_URL}/course/view.php?id={course_id}"
        res = session.get(url)
        res.raise_for_status()
        return parse_course_activities(res.text)

    def get_assignment_detail(self, assign_module_id: int):
        """Return dictionary with submission/due information for a given assignment module."""
        from learnus_parser import parse_assignment_detail

        session = self.ensure_logged_in()
        url = f"{self.BASE_URL}/mod/assign/view.php?id={assign_module_id}"
        res = session.get(url)
        res.raise_for_status()
        return parse_assignment_detail(res.text)

    def get_courses(self):
        """Return list of courses as dicts {id, name}"""
        from learnus_parser import parse_dashboard_courses

        session = self.ensure_logged_in()
        res = session.get(f"{self.BASE_URL}/")
        res.raise_for_status()
        return parse_dashboard_courses(res.text)

    # ------------------------------------------------------------------
    # Internal steps — closely mirror the original snippet
    # ------------------------------------------------------------------
    def _post(self, url: str, headers: dict, data: dict):
        res = self.session.post(url, headers=headers, data=data)
        res.raise_for_status()
        return res

    def _get_input_value(self, res_text: str, name: str) -> Optional[str]:
        soup = BeautifulSoup(res_text, "html.parser")
        tag = soup.find("input", {"name": name})
        return tag["value"] if tag else None

    def _get_multiple_input_values(self, res_text: str, names: list[str]) -> Optional[dict[str, str]]:
        soup = BeautifulSoup(res_text, "html.parser")
        values = {}
        for n in names:
            tag = soup.find("input", {"name": n})
            if tag is None:
                return None
            values[n] = tag["value"]
        return values

    # ----- Step helpers --------------------------------------------------
    def _step_0_coursemos(self, username: str, password: str) -> str:
        headers = {**self._BASE_HEADERS, "Referer": f"{self.BASE_URL}/login/method/sso.php"}
        data = {
            "ssoGubun": "Login",
            "logintype": "sso",
            "type": "popup_login",
            "username": username,
            "password": password,
        }
        res = self._post(f"{self.BASE_URL}/passni/sso/coursemosLogin.php", headers, data)
        s1 = self._get_input_value(res.text, "S1")
        if not s1:
            raise LearnUsLoginError("Failed to obtain S1 in step 0 (possible credential error)")
        return s1

    def _step_1_get_challenge(self, username: str, password: str, s1: str) -> Tuple[str, str]:
        headers = {**self._BASE_HEADERS, "Referer": f"{self.BASE_URL}/"}
        data = {
            "ssoGubun": "Login",
            "logintype": "sso",
            "type": "popup_login",
            "username": username,
            "password": password,
            "app_id": "ednetYonsei",
            "retUrl": self.BASE_URL,
            "failUrl": f"{self.BASE_URL}/login/index.php",
            "baseUrl": self.BASE_URL,
            "S1": s1,
            "loginUrl": f"{self.BASE_URL}/passni/sso/coursemosLogin.php",
            "refererUrl": self.BASE_URL,
            "test": "SSOAuthLogin",
            "loginType": "invokeID",
            "E2": "",
        }
        res = self._post("https://infra.yonsei.ac.kr/sso/PmSSOService", headers, data)
        vals = self._get_multiple_input_values(res.text, ["ssoChallenge", "keyModulus"])
        if vals is None:
            raise LearnUsLoginError("Failed to obtain ssoChallenge/keyModulus in step 1")
        return vals["ssoChallenge"], vals["keyModulus"]

    def _encrypt_credentials(self, username: str, password: str, sc: str, km: str) -> str:
        key_pair = RSA.construct((int(km, 16), 0x10001))
        cipher = PKCS1_v1_5.new(key_pair)
        payload = f'{{"userid":"{username}","userpw":"{password}","ssoChallenge":"{sc}"}}'
        return cipher.encrypt(payload.encode()).hex()

    def _step_2_submit_credentials(self, username: str, password: str, s1: str, sc: str, km: str, e2: str) -> str:
        headers = {**self._BASE_HEADERS, "Referer": "https://infra.yonsei.ac.kr/"}
        data = {
            "ssoGubun": "Login",
            "logintype": "sso",
            "type": "popup_login",
            "username": username,
            "password": password,
            "app_id": "ednetYonsei",
            "retUrl": self.BASE_URL,
            "failUrl": f"{self.BASE_URL}/login/index.php",
            "baseUrl": self.BASE_URL,
            "loginUrl": f"{self.BASE_URL}/passni/sso/coursemosLogin.php",
            "refererUrl": self.BASE_URL,
            "test": "SSOAuthLogin",
            "loginType": "invokeID",
            "E2": e2,
            "S1": s1,
            "ssoChallenge": sc,
            "keyModulus": km,
            "keyExponent": "10001",
        }
        res = self._post(f"{self.BASE_URL}/passni/sso/coursemosLogin.php", headers, data)
        s1 = self._get_input_value(res.text, "S1")
        if not s1:
            raise LearnUsLoginError("Failed to obtain S1 in step 2")
        return s1

    def _step_3_get_tokens(self, username: str, password: str, s1: str) -> Tuple[str, str, str, str]:
        headers = {**self._BASE_HEADERS, "Referer": f"{self.BASE_URL}/"}
        data = {
            "app_id": "ednetYonsei",
            "retUrl": self.BASE_URL,
            "failUrl": f"{self.BASE_URL}/login/index.php",
            "baseUrl": self.BASE_URL,
            "loginUrl": f"{self.BASE_URL}/passni/sso/coursemosLogin.php",
            "S1": s1,
            "ssoGubun": "Login",
            "refererUrl": self.BASE_URL,
            "test": "SSOAuthLogin",
            "username": username,
            "password": password,
        }
        res = self._post("https://infra.yonsei.ac.kr/sso/PmSSOAuthService", headers, data)
        vals = self._get_multiple_input_values(res.text, ["E3", "E4", "S2", "CLTID"])
        if vals is None:
            raise LearnUsLoginError("Failed to get E3/E4/S2/CLTID in step 3")
        return vals["E3"], vals["E4"], vals["S2"], vals["CLTID"]

    def _step_4_finalise(self, username: str, password: str, e3: str, e4: str, s2: str, cltid: str) -> None:
        headers = {**self._BASE_HEADERS, "Referer": "https://infra.yonsei.ac.kr/"}
        data = {
            "app_id": "ednetYonsei",
            "retUrl": self.BASE_URL,
            "failUrl": f"{self.BASE_URL}/login/index.php",
            "baseUrl": self.BASE_URL,
            "loginUrl": f"{self.BASE_URL}/passni/sso/coursemosLogin.php",
            "E3": e3,
            "E4": e4,
            "S2": s2,
            "CLTID": cltid,
            "ssoGubun": "Login",
            "refererUrl": self.BASE_URL,
            "test": "SSOAuthLogin",
            "username": username,
            "password": password,
        }
        self._post(f"{self.BASE_URL}/passni/sso/spLoginData.php", headers, data)
        # Final GET to finish creating the session cookies.
        self.session.get(f"{self.BASE_URL}/passni/spLoginProcess.php") 