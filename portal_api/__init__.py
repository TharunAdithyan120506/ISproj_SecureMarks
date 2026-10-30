"""Portal API: the backend-for-frontend behind the React portal (web/).

Each browser tab sends its own X-Portal-Session id (kept in sessionStorage),
and gets its own SecureClient bound to its device's loopback IP, so a teacher
tab and a student tab side by side are two separate devices on the wire, just
as before. The crypto, signing and device binding stay in the tested Python
SDK; the browser only ever talks to this process on 127.0.0.1:8501.

    uvicorn portal_api.main:app --host 127.0.0.1 --port 8501
"""
