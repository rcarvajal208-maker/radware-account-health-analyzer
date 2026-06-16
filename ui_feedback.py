import os
import base64
import streamlit as st
from contextlib import contextmanager

WORKING_MESSAGE = "Radware is working on your updates..."
SUCCESS_MESSAGE = "Task completed successfully."

WORKING_ICON_PATH = "assets/radware_working.gif"
WORKING_ICON_PATH_2 = "assets/radware_working_2.gif"
SUCCESS_ICON_PATH = "assets/radware_done.gif"


def _image_to_base64(path):
    if not os.path.exists(path):
        return None

    with open(path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode()


@contextmanager
def radware_working(message: str = WORKING_MESSAGE):
    placeholder = st.empty()
    img_base64 = _image_to_base64(WORKING_ICON_PATH)

    if img_base64:
        icon_html = f'<img src="data:image/gif;base64,{img_base64}" style="width:260px; margin-bottom:24px;">'
    else:
        icon_html = '<div style="font-size:90px; margin-bottom:24px;">⏳</div>'

    placeholder.markdown(
        f"""
        <div style="
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(8, 13, 24, 0.88);
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(6px);
        ">
            <div style="
                background: #111827;
                border: 1px solid #374151;
                border-radius: 28px;
                padding: 48px 64px;
                text-align: center;
                box-shadow: 0 24px 80px rgba(0,0,0,0.45);
                color: white;
                max-width: 560px;
            ">
                {icon_html}
                <h2 style="margin:0; font-size:30px;">{message}</h2>
                <p style="margin-top:14px; color:#cbd5e1; font-size:16px;">
                    Please wait while Radware processes your request.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    try:
        yield
    finally:
        placeholder.empty()

def radware_inline_loader(message: str = "Loading application security adoption..."):
    img_base64 = _image_to_base64(WORKING_ICON_PATH_2)

    if img_base64:
        icon_html = (
            f'<img src="data:image/gif;base64,{img_base64}" '
            f'style="width:120px; height:120px; object-fit:contain; margin-right:18px;">'
        )
    else:
        icon_html = '<span style="font-size:32px; margin-right:12px;">⏳</span>'

    return st.empty().markdown(
        f"""
        <div style="
            display:flex;
            align-items:center;
            gap:10px;
            margin:8px 0 10px 0;
        ">
            {icon_html}
            <span style="font-size:16px; font-weight:600; color:#e5e7eb;">
                {message}
            </span>
        </div>
        """,
        unsafe_allow_html=True
    )

def radware_success(message: str = SUCCESS_MESSAGE):
    img_base64 = _image_to_base64(SUCCESS_ICON_PATH)

    if img_base64:
        icon_html = f'<img src="data:image/gif;base64,{img_base64}" style="width:220px; margin-bottom:20px;">'
    else:
        icon_html = '<div style="font-size:80px; margin-bottom:20px;">✅</div>'

    st.markdown(
        f"""
        <div style="
            background: #052e16;
            border: 1px solid #22c55e;
            border-radius: 24px;
            padding: 36px;
            text-align: center;
            margin: 24px 0;
            color: white;
        ">
            {icon_html}
            <h2 style="margin:0;">{message}</h2>
        </div>
        """,
        unsafe_allow_html=True
    )