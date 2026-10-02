from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import engine, SessionLocal
from models import Base, ScamReport

import json


app = FastAPI()


# Frontend ko backend API access karne ki permission
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Database table create karna
Base.metadata.create_all(bind=engine)


# User se milne wali information
class ScamInput(BaseModel):

    caller_claim: str
    claimed_authority: bool
    threatened_arrest: bool
    demanded_money: bool
    asked_otp_bank: bool
    forced_video_call: bool
    asked_install_app: bool
    created_urgency: bool


# Backend test karne ke liye
@app.get("/")
def home():

    return {
        "message": "Digital Arrest Backend is Running"
    }


# Digital Arrest information receive karne wali API
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


    # Risk level
    if risk_score >= 60:

        risk_level = "HIGH"

    elif risk_score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # Scam detected
    scam_detected = risk_score >= 30


    # Safety actions
    safety_actions = [

        "Do not transfer money.",

        "End the call.",

        "Do not share OTP, passwords, or bank details.",

        "Verify the caller independently.",

        "Report the incident through appropriate official channels."

    ]


    # Database connection
    db = SessionLocal()


    # Report create karna
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


    # Database me save
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


# Saari reports dekhne wali API
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


# Ek particular report ID se report dekhne wali API
@app.get("/reports/{report_id}")
def get_report(report_id: int):

    db = SessionLocal()


    # Database me ID search karna
    report = db.query(ScamReport).filter(
        ScamReport.id == report_id
    ).first()


    # Agar report nahi mili
    if report is None:

        db.close()

        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )


    # Report mil gayi
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