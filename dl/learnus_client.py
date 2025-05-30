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
        """Perform Yonsei SSO login using the *correct 2025* flow.

        The 2025 flow now provides RSA keys via JavaScript instead of hidden inputs:
        1. Get S1 from spLogin2.php (with proper Referer header)
        2. Submit to PmSSOService to get login form with JavaScript RSA keys
        3. Extract ssoChallenge and keyModulus from JavaScript
        4. Encrypt credentials using RSA and submit to PmSSOAuthService
        5. Finalize with spLoginData.php and spLoginProcess.php
        """
        import requests  # local import to be explicit
        import re

        session = requests.Session()
        base_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        }

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

        def extract_js_rsa_keys(html_text: str):
            """Extract ssoChallenge and RSA modulus from JavaScript code."""
            # Extract ssoChallenge
            challenge_match = re.search(r"var ssoChallenge\s*=\s*['\"]([^'\"]+)['\"]", html_text)
            if not challenge_match:
                raise LearnUsLoginError("ssoChallenge not found in JavaScript")
            
            # Extract RSA public key (modulus)
            # Look for the full hex string in setPublic call
            modulus_match = re.search(r"rsa\.setPublic\s*\(\s*['\"]([0-9a-fA-F]+)['\"]", html_text)
            if not modulus_match:
                raise LearnUsLoginError("RSA modulus not found in JavaScript")
            
            return challenge_match.group(1), modulus_match.group(1)

        # Step 0: Establish proper session by visiting main page and login page
        headers = base_headers.copy()
        logger.info("[LearnUs] Establishing session...")
        
        # Visit main page first
        session.get(f"{self.BASE_URL}/", headers=headers)
        
        # Visit login page to establish proper referrer chain
        headers["Referer"] = f"{self.BASE_URL}/"
        session.get(f"{self.BASE_URL}/login/index.php", headers=headers)

        # Step 1: Get S1 from spLogin2.php (now with proper Referer)
        headers["Referer"] = f"{self.BASE_URL}/login/index.php"
        res = session.get(f"{self.BASE_URL}/passni/sso/spLogin2.php", headers=headers)
        res.raise_for_status()
        s1 = get_value_from_input(res.text, "S1")
        if not s1:
            raise LearnUsLoginError("Failed to obtain S1 from spLogin2.php")

        # Step 2: Submit to PmSSOService to get login form with JavaScript RSA keys
        headers["Referer"] = f"{self.BASE_URL}/passni/sso/spLogin2.php"
        data = {
            "app_id": "ednetYonsei",
            "retUrl": self.BASE_URL,
            "failUrl": self.BASE_URL,
            "baseUrl": self.BASE_URL,
            "S1": s1,
            "ssoGubun": "",
            "refererUrl": "",
        }
        res = post_request("https://infra.yonsei.ac.kr/sso/PmSSOService", headers, data)
        
        # Step 3: Extract RSA keys from JavaScript in the response
        try:
            sso_challenge, key_modulus = extract_js_rsa_keys(res.text)
        except LearnUsLoginError:
            raise LearnUsLoginError("Failed to extract RSA keys from PmSSOService JavaScript")
        
        # Step 4: Encrypt credentials using RSA (same as before)
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_v1_5
        
        key_pair = RSA.construct((int(key_modulus, 16), 0x10001))
        cipher = PKCS1_v1_5.new(key_pair)
        payload = f'{{"userid":"{username}","userpw":"{password}","ssoChallenge":"{sso_challenge}"}}'
        e2 = cipher.encrypt(payload.encode()).hex()
        
        # Extract form data from the login form
        soup = BeautifulSoup(res.text, "html.parser")
        form = soup.find("form", {"action": "/sso/PmSSOAuthService"})
        if not form:
            raise LearnUsLoginError("PmSSOAuthService form not found in PmSSOService response")
        
        # Get all hidden inputs from the form
        form_data = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            value = inp.get("value", "")
            if name and inp.get("type") == "hidden":
                form_data[name] = value
        
        # Step 5: Submit encrypted credentials to PmSSOAuthService
        headers["Referer"] = "https://infra.yonsei.ac.kr/sso/PmSSOService"
        form_data.update({
            "loginId": username,
            "loginPasswd": password,
            "E2": e2,  # This was the missing piece!
        })
        res = post_request("https://infra.yonsei.ac.kr/sso/PmSSOAuthService", headers, form_data)
        
        # Extract E3, E4, S2, CLTID from the response
        vals = get_multiple_values(res.text, ["E3", "E4", "S2", "CLTID"])
        if not vals:
            raise LearnUsLoginError("Failed to obtain E3/E4/S2/CLTID from PmSSOAuthService")
        e3, e4, s2, cltid = vals["E3"], vals["E4"], vals["S2"], vals["CLTID"]

        # Step 6: Finalize login with spLoginData.php
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
        
        # Step 7: Complete session with spLoginProcess.php
        session.get(f"{self.BASE_URL}/passni/spLoginProcess.php")

        # Success – store session
        self.session = session
        logger.info("[LearnUs] Authenticated as %s using 2025 flow (with proper Referer headers)", username)

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