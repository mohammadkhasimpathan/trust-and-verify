function getPromptTemplate(operation) {
  const templates = {
    RISK_EXPLAINER: "Explain this risk score based on the deterministic indicators.",
    INCIDENT_ANALYST: "Analyze this incident context and identify possible attack patterns.",
    INVESTIGATION_ASSISTANT: "Suggest next steps for this investigation based on the evidence.",
    THREAT_HUNTER: "Generate hunting queries to detect this threat.",
    REPORT_ASSISTANT: "Summarize this security data."
  };
  return templates[operation] || "Analyze the following security data.";
}

module.exports = {
  getPromptTemplate
};
