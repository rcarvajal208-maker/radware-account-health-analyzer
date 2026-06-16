import requests
from typing import Optional, Dict, Any


class RadwareClient:
    def __init__(self, api_key: str, context: str, base_url: str):
        self.api_key = api_key
        self.context = context
        self.base_url = base_url.rstrip("/")
        self.console_url = "https://console.radwarecloud.com"

        self.headers = {
            "x-api-key": self.api_key,
            "context": self.context,
            "requestEntityIds": self.context,
            "Content-Type": "application/json",
            "User-Agent": "Radware-Account-Health-Analyzer/1.0",
        }

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None):
        url = f"{self.base_url}{endpoint}"
        response = requests.get(
            url,
            headers=self.headers,
            params=params,
            timeout=30,
        )
        return self._handle_response(response)

    def get_console(self, endpoint: str, params: Optional[Dict[str, Any]] = None):
        """
        Test console-origin endpoints captured from the UI.

        Note: many console endpoints require browser session authentication and may not
        accept API key authentication. This method is kept only for controlled discovery.
        """
        url = f"{self.console_url}{endpoint}"
        response = requests.get(
            url,
            headers=self.headers,
            params=params,
            timeout=30,
        )
        return self._handle_response(response)

    def post(self, endpoint: str, payload: Dict[str, Any]):
        url = f"{self.base_url}{endpoint}"
        response = requests.post(
            url,
            headers=self.headers,
            json=payload,
            timeout=30,
        )
        return self._handle_response(response)

    def post_console(self, endpoint: str, payload: Optional[Dict[str, Any]] = None):
        """Console endpoint POST helper for discovery only."""
        url = f"{self.console_url}{endpoint}"
        response = requests.post(
            url,
            headers=self.headers,
            json=payload,
            timeout=30,
        )
        return self._handle_response(response)

    def _handle_response(self, response: requests.Response):
        try:
            data = response.json()
        except Exception:
            data = response.text

        if not response.ok:
            raise Exception({
                "status_code": response.status_code,
                "response": data,
            })

        return data
