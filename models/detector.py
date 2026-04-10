import re

class DataLeakDetector:
    def __init__(self):
        self.patterns = {
            "Credit Card Number": {
                "regex": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6011[0-9]{12})\b',
                "risk": "HIGH",
                "emoji": "💳"
            },
            "Social Security Number (SSN)": {
                "regex": r'\b\d{3}-\d{2}-\d{4}\b',
                "risk": "HIGH",
                "emoji": "🪪"
            },
            "Email Address": {
                "regex": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "risk": "MEDIUM",
                "emoji": "📧"
            },
            "Phone Number": {
                "regex": r'\b(?:\+91[-\s]?)?[6-9]\d{9}\b|\b\+?1?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
                "risk": "MEDIUM",
                "emoji": "📞"
            },
            "API Key / Token": {
                "regex": r'\b(?:sk|pk|api|token|key)[-_]?[A-Za-z0-9]{20,}\b',
                "risk": "HIGH",
                "emoji": "🔑"
            },
            "IP Address": {
                "regex": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                "risk": "LOW",
                "emoji": "🌐"
            },
            "Aadhaar Number": {
                "regex": r'\b[2-9]{1}[0-9]{11}\b',
                "risk": "HIGH",
                "emoji": "🪪"
            },
            "Password (plaintext)": {
                "regex": r'(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+',
                "risk": "HIGH",
                "emoji": "🔒"
            },
            "Bank Account Number": {
                "regex": r'\b\d{9,18}\b',
                "risk": "MEDIUM",
                "emoji": "🏦"
            },
            "Date of Birth": {
                "regex": r'\b(?:dob|date of birth|birth date)\s*[:=]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
                "risk": "MEDIUM",
                "emoji": "🎂"
            }
        }

    def scan_text(self, text):
        findings = []
        risk_score = 0
        risk_weights = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

        for label, config in self.patterns.items():
            matches = re.findall(config["regex"], text)
            if matches:
                # Mask the matched values
                masked = [self._mask(m) for m in matches[:3]]
                findings.append({
                    "type": label,
                    "emoji": config["emoji"],
                    "risk": config["risk"],
                    "count": len(matches),
                    "samples": masked
                })
                risk_score += risk_weights[config["risk"]] * len(matches)

        if risk_score == 0:
            risk_level = "SAFE"
        elif risk_score <= 3:
            risk_level = "LOW"
        elif risk_score <= 8:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        return {
            "findings": findings,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "total_matches": sum(f["count"] for f in findings),
            "summary": self._generate_summary(findings, risk_level)
        }

    def _mask(self, value):
        s = str(value)
        if len(s) <= 4:
            return "*" * len(s)
        return s[:2] + "*" * (len(s) - 4) + s[-2:]

    def _generate_summary(self, findings, risk_level):
        if not findings:
            return "✅ No sensitive data detected. Content appears safe."
        types = [f["type"] for f in findings]
        return f"⚠️ Detected {len(findings)} sensitive data type(s): {', '.join(types)}. Risk Level: {risk_level}"
