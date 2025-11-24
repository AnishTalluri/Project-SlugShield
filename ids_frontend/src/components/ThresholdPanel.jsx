import React, { useState } from "react";

export default function ThresholdPanel() {
  const [sshValue, setSshValue] = useState("");
  const [icmpValue, setIcmpValue] = useState("");
  const [arpValue, setArpValue] = useState("");

  async function updateThreshold(detector, value) {
    if (!value) return alert("Please enter a value.");

    const res = await fetch("http://127.0.0.1:8080/set_threshold", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        detector_name: detector,
        new_value: parseInt(value),
      }),
    });

    const data = await res.json();
    if (data.status === "ok") {
      alert(`Updated ${detector.toUpperCase()} threshold successfully!`);
    } else {
      alert("Error updating threshold.");
    }
  }

  return (
    <div style={panelStyle}>
      <h3 style={headingStyle}>Threshold Settings</h3>

      <div style={rowStyle}>
        <label style={labelStyle}>SSH Threshold:</label>
        <input
          type="number"
          value={sshValue}
          onChange={(e) => setSshValue(e.target.value)}
          style={inputStyle}
        />
        <button
          onClick={() => updateThreshold("ssh", sshValue)}
          style={buttonStyle}
        >
          Update
        </button>
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>ICMP Threshold:</label>
        <input
          type="number"
          value={icmpValue}
          onChange={(e) => setIcmpValue(e.target.value)}
          style={inputStyle}
        />
        <button
          onClick={() => updateThreshold("icmp", icmpValue)}
          style={buttonStyle}
        >
          Update
        </button>
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>ARP Threshold:</label>
        <input
          type="number"
          value={arpValue}
          onChange={(e) => setArpValue(e.target.value)}
          style={inputStyle}
        />
        <button
          onClick={() => updateThreshold("arp", arpValue)}
          style={buttonStyle}
        >
          Update
        </button>
      </div>
    </div>
  );
}

/* === Styles === */
const panelStyle = {
  border: "1px solid #ddd",
  borderRadius: "10px",
  padding: "20px",
  background: "#fff",
  width: "100%",
  boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
  marginTop: "20px",
};

const headingStyle = {
  marginBottom: "20px",
  fontSize: "20px",
  fontWeight: "600",
};

const rowStyle = {
  display: "grid",
  gridTemplateColumns: "140px 1fr 120px",
  alignItems: "center",
  gap: "10px",
  marginBottom: "15px",
};

const labelStyle = {
  fontWeight: "500",
};

const inputStyle = {
  padding: "6px 8px",
  fontSize: "15px",
  borderRadius: "6px",
  border: "1px solid #ccc",
};

const buttonStyle = {
  padding: "6px 10px",
  border: "none",
  background: "#007bff",
  color: "white",
  borderRadius: "6px",
  cursor: "pointer",
};
