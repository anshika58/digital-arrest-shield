from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List
from ai_agent import get_ai_advice
from database import engine, SessionLocal
from models import Base, ScamReport

from pathlib import Path
import json


app = FastAPI()


# =====================================================
# FRONTEND LOCATION
# =====================================================

FRONTEND_DIR = Path(__file__).resolve().parent / "fronted"


# =====================================================
# NO GOOGLE INDEXING
# =====================================================

@app.middleware("http")
async def add_noindex_header(request, call_next):

    response = await call_next(request)

    response.headers["X-Robots-Tag"] = "noindex, nofollow"

    return response


# =====================================================
# CORS
# =====================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================
# DATABASE
# =====================================================

Base.metadata.create_all(bind=engine)


# =====================================================
# FRONTEND
# =====================================================

@app.get("/", include_in_schema=False)
def home():

    return FileResponse(
        FRONTEND_DIR / "index.html"
    )


@app.get("/style.css", include_in_schema=False)
def style():

    return FileResponse(
        FRONTEND_DIR / "style.css",
        media_type="text/css"
    )


@app.get("/script.js", include_in_schema=False)
def script():

    return FileResponse(
        FRONTEND_DIR / "script.js",
        media_type="application/javascript"
    )


# =====================================================
# USER INPUT MODEL
# =====================================================

class ScamInput(BaseModel):

    caller_claim: str
    claimed_authority: bool
    threatened_arrest: bool
    demanded_money: bool
    asked_otp_bank: bool
    forced_video_call: bool
    asked_install_app: bool
    created_urgency: bool


# =====================================================
# DIGITAL ARREST DETECTION
# =====================================================

@app.post("/detect-scam")
def detect_scam(data: ScamInput):

    risk_score = 0
    red_flags = []


    if data.claimed_authority:

        risk_score += 20
        red_flags.append("Authority impersonation")


    if data.threatened_arrest:

        risk_score += 20
        red_flags.append("Threat of arrest")


    if data.demanded_money:

        risk_score += 20
        red_flags.append("Money demand")


    if data.asked_otp_bank:

        risk_score += 20
        red_flags.append("OTP or bank details requested")


    if data.forced_video_call:

        risk_score += 10
        red_flags.append("Forced video call")


    if data.asked_install_app:

        risk_score += 5
        red_flags.append("Asked to install an application")


    if data.created_urgency:

        risk_score += 5
        red_flags.append("Created urgency or pressure")


    # =================================================
    # RISK LEVEL
    # =================================================

    if risk_score >= 60:

        risk_level = "HIGH"

    elif risk_score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    scam_detected = risk_score >= 30


    # =================================================
    # SAFETY ACTIONS
    # =================================================

    safety_actions = [

        "Do not transfer money.",

        "End the call.",

        "Do not share OTP, passwords, or bank details.",

        "Verify the caller independently.",

        "Report the incident through appropriate official channels."

    ]


    # =================================================
    # DATABASE
    # =================================================

    db = SessionLocal()


    report = ScamReport(

        caller_claim=data.caller_claim,

        claimed_authority=data.claimed_authority,

        threatened_arrest=data.threatened_arrest,

        demanded_money=data.demanded_money,

        asked_otp_bank=data.asked_otp_bank,

        forced_video_call=data.forced_video_call,

        asked_install_app=data.asked_install_app,

        created_urgency=data.created_urgency,

        risk_score=risk_score,

        risk_level=risk_level,

        red_flags=json.dumps(red_flags)

    )


    db.add(report)

    db.commit()

    db.refresh(report)

    db.close()


    return {

        "message": "Scam report saved successfully",

        "report_id": report.id,

        "scam_detected": scam_detected,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "red_flags": red_flags,

        "safety_actions": safety_actions

    }


# =====================================================
# AI ADVICE INPUT
# =====================================================

class AdviceInput(BaseModel):

    user_question: str = ""

    risk_score: int = 0

    risk_level: str = "LOW"

    red_flags: List[str] = []


# =====================================================
# AI SAFETY ADVICE
# =====================================================

@app.post("/ai-advice")
def ai_advice(data: AdviceInput):

    advice = get_ai_advice(

        user_question=data.user_question,

        risk_score=data.risk_score,

        risk_level=data.risk_level,

        red_flags=data.red_flags

    )


    return {

        "advice": advice

    }


# =====================================================
# ALL REPORTS
# =====================================================

@app.get("/reports")
def get_reports():

    db = SessionLocal()

    reports = db.query(ScamReport).all()

    result = []


    for report in reports:

        result.append({

            "report_id": report.id,

            "caller_claim": report.caller_claim,

            "claimed_authority": report.claimed_authority,

            "threatened_arrest": report.threatened_arrest,

            "demanded_money": report.demanded_money,

            "asked_otp_bank": report.asked_otp_bank,

            "forced_video_call": report.forced_video_call,

            "asked_install_app": report.asked_install_app,

            "created_urgency": report.created_urgency,

            "risk_score": report.risk_score,

            "risk_level": report.risk_level,

            "red_flags": json.loads(report.red_flags)

        })


    db.close()


    return {

        "total_reports": len(result),

        "reports": result

    }


# =====================================================
# SINGLE REPORT
# =====================================================

@app.get("/reports/{report_id}")
def get_report(report_id: int):

    db = SessionLocal()


    report = db.query(ScamReport).filter(
        ScamReport.id == report_id
    ).first()


    if report is None:

        db.close()

        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )


    result = {

        "report_id": report.id,

        "caller_claim": report.caller_claim,

        "claimed_authority": report.claimed_authority,

        "threatened_arrest": report.threatened_arrest,

        "demanded_money": report.demanded_money,

        "asked_otp_bank": report.asked_otp_bank,

        "forced_video_call": report.forced_video_call,

        "asked_install_app": report.asked_install_app,

        "created_urgency": report.created_urgency,

        "risk_score": report.risk_score,

        "risk_level": report.risk_level,

        "red_flags": json.loads(report.red_flags)

    }


    db.close()


    return result