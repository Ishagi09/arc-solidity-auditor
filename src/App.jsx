import { useState, useEffect } from "react";

const RULES = [
  {
    id: "prevrandao", pattern: /block\.prevrandao|PREV_RANDAO/g, severity: "critical",
    title: "Randomness always returns 0", short: "block.prevrandao = 0",
    description: "Arc sets block.prevrandao to 0 permanently — no beacon chain. Any contract using this for randomness is instantly exploitable.",
    fix: "Use Chainlink VRF or another onchain oracle for randomness on Arc.",
    docs: "https://docs.arc.network/arc/references/evm-compatibility",
  },
  {
    id: "selfdestruct", pattern: /selfdestruct\s*\(/g, severity: "critical",
    title: "SELFDESTRUCT restricted on Arc", short: "selfdestruct() reverts",
    description: "Arc blocks SELFDESTRUCT during deployment to prevent USDC burns. Contracts calling this will revert.",
    fix: "Replace with a withdrawal + pause pattern.",
    docs: "https://docs.arc.network/arc/references/evm-compatibility",
  },
  {
    id: "eth-value", pattern: /\d+\s*(ether|gwei|wei)\b|\bmsg\.value\b/g, severity: "warning",
    title: "ETH denomination detected", short: "Gas is USDC, not ETH",
    description: "Arc uses USDC as native gas. ETH denominations behave incorrectly.",
    fix: "Use USDC denominations. 1e6 for ERC-20 USDC, 1e18 for native.",
    docs: "https://docs.arc.network/arc/concepts/stable-fee-design",
  },
  {
    id: "blob", pattern: /blobhash\s*\(|EIP.?4844|blob_base_fee/gi, severity: "warning",
    title: "EIP-4844 blobs disabled", short: "Blob txns not supported",
    description: "Arc does not support EIP-4844. Blob-related logic will fail silently or revert.",
    fix: "Use standard calldata instead.",
    docs: "https://docs.arc.network/arc/references/evm-compatibility",
  },
  {
    id: "timestamp", pattern: /block\.timestamp\s*[<>]=?\s*|[<>]=?\s*block\.timestamp/g, severity: "warning",
    title: "Timestamp ordering unsafe", short: "Blocks share timestamps",
    description: "Arc sub-second blocks can share the same wall-clock timestamp. Strict comparisons break.",
    fix: "Use block numbers for ordering, or add tolerance buffers.",
    docs: "https://docs.arc.network/arc/references/evm-compatibility",
  },
  {
    id: "transfer-send", pattern: /\.transfer\s*\(|\.send\s*\(/g, severity: "warning",
    title: "ETH transfer pattern", short: ".transfer()/.send() — check intent",
    description: "Gas stipends differ from Ethereum. Ensure you intend native USDC, not ERC-20.",
    fix: "Use IERC20(USDC_ADDRESS).transfer() for ERC-20 USDC explicitly.",
    docs: "https://docs.arc.network/arc/references/contract-addresses",
  },
  {
    id: "decimal", pattern: /10\s*\*\*\s*18|1e18|\bdecimals\(\)/gi, severity: "info",
    title: "USDC decimal mismatch risk", short: "Native=18dec, ERC-20=6dec",
    description: "Native USDC uses 18 decimals, ERC-20 uses 6. Mixing causes 1e12x amount errors.",
    fix: "Use 1e6 for ERC-20 USDC, 1e18 for native. Never assume.",
    docs: "https://docs.arc.network/arc/references/evm-compatibility#erc20-interface",
  },
  {
    id: "blockhash", pattern: /blockhash\s*\(|block\.difficulty/g, severity: "info",
    title: "Weak randomness source", short: "blockhash exploitable",
    description: "Weak randomness on any EVM, worse on Arc with permissioned validators.",
    fix: "Use Chainlink VRF or commit-reveal schemes.",
    docs: "https://docs.arc.network/arc/references/evm-compatibility",
  },
];

const SEV = {
  critical: { color: "#FF4D6D", bg: "rgba(255,77,109,0.07)", border: "rgba(255,77,109,0.22)", icon: "✕", label: "CRITICAL", dim: "rgba(255,77,109,0.4)" },
  warning:  { color: "#FFB830", bg: "rgba(255,184,48,0.07)",  border: "rgba(255,184,48,0.22)",  icon: "⚠", label: "WARNING",  dim: "rgba(255,184,48,0.4)" },
  info:     { color: "#60A5FA", bg: "rgba(96,165,250,0.07)",  border: "rgba(96,165,250,0.22)",  icon: "i", label: "INFO",     dim: "rgba(96,165,250,0.4)" },
};

const SAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableOnArc {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() { owner = msg.sender; }

    // CRITICAL: prevrandao is always 0 on Arc
    function pickWinner(address[] memory players) public view returns (address) {
        uint256 rand = uint256(block.prevrandao) % players.length;
        return players[rand];
    }

    // CRITICAL: SELFDESTRUCT reverts on Arc
    function destroy() external {
        require(msg.sender == owner);
        selfdestruct(payable(owner));
    }

    // WARNING: ETH denomination — Arc uses USDC as gas
    function deposit() external payable {
        require(msg.value >= 0.01 ether, "min 0.01 ETH");
        balances[msg.sender] += msg.value;
    }

    // WARNING: Timestamp strict ordering unsafe
    function isExpired(uint256 deadline) public view returns (bool) {
        return block.timestamp > deadline;
    }

    // INFO: 1e18 — ERC-20 USDC uses 6 decimals not 18
    function toUSDC(uint256 amount) public pure returns (uint256) {
        return amount * 1e18;
    }

    // INFO: weak randomness
    function quickRand() public view returns (uint256) {
        return uint256(blockhash(block.number - 1));
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}`;

function scanCode(code) {
  const lines = code.split("\n");
  const results = [];
  RULES.forEach(rule => {
    rule.pattern.lastIndex = 0;
    const pat = new RegExp(rule.pattern.source, rule.pattern.flags);
    let m;
    while ((m = pat.exec(code)) !== null) {
      const before = code.slice(0, m.index).split("\n");
      const ln = before.length;
      if (!results.find(r => r.ruleId === rule.id && r.line === ln)) {
        results.push({ ruleId: rule.id, rule, line: ln, lineContent: (lines[ln - 1] || "").trim(), match: m[0] });
      }
    }
  });
  return results.sort((a, b) => ({ critical: 0, warning: 1, info: 2 }[a.rule.severity] - { critical: 0, warning: 1, info: 2 }[b.rule.severity] || a.line - b.line));
}

async function fetchContractFromArcScan(address) {
  // ArcScan is Blockscout-based: testnet.arcscan.app
  const url = `https://testnet.arcscan.app/api/v2/smart-contracts/${address}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`ArcScan returned ${res.status}`);
  const data = await res.json();
  // Blockscout returns source_code field for verified contracts
  if (data.source_code) return { code: data.source_code, name: data.name || "Contract", address };
  // Try additional_sources for multi-file contracts
  if (data.additional_sources?.length > 0) {
    const combined = data.additional_sources.map(s => `// File: ${s.file_path}\n${s.source_code}`).join("\n\n");
    return { code: combined, name: data.name || "Contract", address };
  }
  throw new Error("Contract source not verified on ArcScan. Only verified contracts can be audited.");
}

async function getAIExplanation(finding, code) {
  const lines = code.split("\n");
  const ctx = lines.slice(Math.max(0, finding.line - 3), finding.line + 2).join("\n");
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      messages: [{
        role: "user",
        content: `You are an Arc blockchain (by Circle) security expert. Issue found:

${finding.rule.severity.toUpperCase()}: ${finding.rule.title}
Line ${finding.line}: ${finding.lineContent}

Context:
\`\`\`solidity\n${ctx}\n\`\`\`

Arc reason: ${finding.rule.description}

In 2-3 sentences: (1) what exactly breaks on Arc, (2) exact fix. Technical, direct, no preamble.`,
      }],
    }),
  });
  const d = await res.json();
  return d.content?.[0]?.text || finding.rule.description;
}

function ScoreRing({ score, critical }) {
  const color = critical > 0 ? "#FF4D6D" : score >= 80 ? "#00E5A0" : "#FFB830";
  const r = 28, c = 2 * Math.PI * r, dash = (score / 100) * c;
  return (
    <svg width={72} height={72} style={{ transform: "rotate(-90deg)", flexShrink: 0 }}>
      <circle cx={36} cy={36} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={5} />
      <circle cx={36} cy={36} r={r} fill="none" stroke={color} strokeWidth={5}
        strokeDasharray={`${dash} ${c}`} strokeLinecap="round"
        style={{ transition: "stroke-dasharray 1s ease" }} />
      <text x={36} y={41} textAnchor="middle" fill={color}
        style={{ fontSize: 16, fontWeight: 900, transform: "rotate(90deg)", transformOrigin: "36px 36px", fontFamily: "Georgia, serif" }}>
        {score}
      </text>
    </svg>
  );
}

// ─── INPUT MODE TOGGLE ────────────────────────────────────────────────────────
function InputToggle({ mode, onChange }) {
  return (
    <div style={{ display: "flex", gap: 2, background: "rgba(255,255,255,0.04)", borderRadius: 4, padding: 3 }}>
      {[{ id: "paste", label: "📋 Paste Code" }, { id: "address", label: "🔍 Contract Address" }].map(({ id, label }) => (
        <button key={id} onClick={() => onChange(id)} style={{
          padding: "5px 14px", borderRadius: 3, border: "none", cursor: "pointer",
          background: mode === id ? "rgba(0,229,160,0.12)" : "transparent",
          color: mode === id ? "#00E5A0" : "rgba(255,255,255,0.3)",
          fontSize: 11, fontWeight: mode === id ? 800 : 400,
          fontFamily: "'Courier New', monospace", letterSpacing: "0.5px",
          border: mode === id ? "1px solid rgba(0,229,160,0.3)" : "1px solid transparent",
          transition: "all 0.15s",
        }}>{label}</button>
      ))}
    </div>
  );
}

export default function ArcAuditor() {
  const [inputMode, setInputMode] = useState("paste"); // paste | address
  const [code, setCode] = useState("");
  const [addressInput, setAddressInput] = useState("");
  const [fetchedMeta, setFetchedMeta] = useState(null); // { name, address }
  const [fetchError, setFetchError] = useState(null);
  const [fetching, setFetching] = useState(false);
  const [findings, setFindings] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [scanned, setScanned] = useState(false);
  const [selected, setSelected] = useState(null);
  const [aiText, setAiText] = useState({});
  const [aiLoading, setAiLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => { setTimeout(() => setLoaded(true), 100); }, []);

  const reset = () => { setFindings([]); setScanned(false); setSelected(null); setFetchError(null); };

  const handleAddressFetch = async () => {
    const addr = addressInput.trim();
    if (!addr) return;
    if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) { setFetchError("Invalid address format. Must be 0x + 40 hex chars."); return; }
    setFetching(true); setFetchError(null); reset();
    try {
      const result = await fetchContractFromArcScan(addr);
      setCode(result.code);
      setFetchedMeta({ name: result.name, address: result.address });
      setInputMode("paste");
    } catch (e) {
      setFetchError(e.message || "Failed to fetch. Contract may not be verified on ArcScan.");
    } finally { setFetching(false); }
  };

  const runScan = () => {
    if (!code.trim() || scanning) return;
    setScanning(true); setScanned(false); setFindings([]); setSelected(null);
    setTimeout(() => { setFindings(scanCode(code)); setScanning(false); setScanned(true); }, 1400);
  };

  const selectIssue = async (f) => {
    setSelected(f);
    const key = `${f.ruleId}-${f.line}`;
    if (!aiText[key]) {
      setAiLoading(true);
      const t = await getAIExplanation(f, code).catch(() => f.rule.description);
      setAiText(p => ({ ...p, [key]: t }));
      setAiLoading(false);
    }
  };

  const critCount = findings.filter(f => f.rule.severity === "critical").length;
  const warnCount = findings.filter(f => f.rule.severity === "warning").length;
  const infoCount = findings.filter(f => f.rule.severity === "info").length;
  const score = scanned ? Math.max(0, 100 - critCount * 28 - warnCount * 10 - infoCount * 4) : 0;
  const issueLines = new Set(findings.map(f => f.line));
  const codeLines = code.split("\n");
  const selKey = selected ? `${selected.ruleId}-${selected.line}` : null;

  return (
    <div style={{
      fontFamily: "'Courier New', monospace", background: "#07090E",
      minHeight: "100vh", color: "#E2E8F0", display: "flex", flexDirection: "column",
      opacity: loaded ? 1 : 0, transition: "opacity 0.5s",
    }}>
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none",
        backgroundImage: "linear-gradient(rgba(0,229,160,0.018) 1px, transparent 1px), linear-gradient(90deg, rgba(0,229,160,0.018) 1px, transparent 1px)",
        backgroundSize: "44px 44px",
      }} />

      {/* TOP BAR */}
      <div style={{
        height: 54, display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 20px", borderBottom: "1px solid rgba(255,255,255,0.05)",
        background: "rgba(7,9,14,0.97)", backdropFilter: "blur(10px)",
        position: "sticky", top: 0, zIndex: 20, flexShrink: 0, gap: 12,
      }}>
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
          <div style={{
            width: 30, height: 30, borderRadius: 5,
            background: "linear-gradient(135deg, rgba(0,229,160,0.15), rgba(0,229,160,0.04))",
            border: "1px solid rgba(0,229,160,0.25)",
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15,
          }}>⬡</div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 900, letterSpacing: "-0.4px", color: "#F1F5F9" }}>Arc Solidity Auditor</div>
            <div style={{ fontSize: 9, color: "rgba(255,255,255,0.2)", letterSpacing: "2px" }}>ARC NETWORK · COMPATIBILITY SCANNER</div>
          </div>
        </div>

        {/* Center — Input toggle */}
        <InputToggle mode={inputMode} onChange={m => { setInputMode(m); reset(); }} />

        {/* Right — actions */}
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
          <button onClick={() => { setCode(SAMPLE); setFetchedMeta(null); reset(); setInputMode("paste"); }} style={{
            padding: "5px 12px", background: "transparent",
            border: "1px solid rgba(255,255,255,0.09)", borderRadius: 3,
            color: "rgba(255,255,255,0.3)", fontSize: 10, cursor: "pointer",
            fontFamily: "inherit", letterSpacing: "1.5px",
          }}>SAMPLE</button>
          <button onClick={runScan} disabled={!code.trim() || scanning} style={{
            padding: "6px 18px", borderRadius: 3,
            background: code.trim() && !scanning ? "rgba(0,229,160,0.1)" : "rgba(255,255,255,0.03)",
            border: `1px solid ${code.trim() && !scanning ? "rgba(0,229,160,0.6)" : "rgba(255,255,255,0.07)"}`,
            color: code.trim() && !scanning ? "#00E5A0" : "rgba(255,255,255,0.18)",
            fontSize: 10, fontWeight: 800, letterSpacing: "2px",
            fontFamily: "inherit", cursor: code.trim() && !scanning ? "pointer" : "not-allowed", transition: "all 0.2s",
          }}>{scanning ? "SCANNING…" : "RUN AUDIT →"}</button>
        </div>
      </div>

      {/* SCAN BAR */}
      <div style={{ height: 2, flexShrink: 0, overflow: "hidden", background: "transparent" }}>
        {scanning && <div style={{ height: "100%", background: "linear-gradient(90deg,transparent,#00E5A0,transparent)", animation: "sweep 1.1s ease-in-out infinite" }} />}
        {scanned && !scanning && <div style={{ height: "100%", background: critCount > 0 ? "#FF4D6D" : "#00E5A0", width: "100%" }} />}
        {fetching && <div style={{ height: "100%", background: "linear-gradient(90deg,transparent,#60A5FA,transparent)", animation: "sweep 1.1s ease-in-out infinite" }} />}
      </div>

      {/* MAIN */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden", minHeight: 0 }}>

        {/* ── LEFT: ADDRESS INPUT or CODE EDITOR ── */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", borderRight: "1px solid rgba(255,255,255,0.05)", minWidth: 0 }}>

          {/* Address Mode */}
          {inputMode === "address" && (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 32, gap: 20 }}>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 28, marginBottom: 10 }}>🔍</div>
                <div style={{ fontSize: 15, fontWeight: 800, color: "rgba(255,255,255,0.7)", marginBottom: 6 }}>
                  Fetch Contract from ArcScan
                </div>
                <div style={{ fontSize: 12, color: "rgba(255,255,255,0.25)", lineHeight: 1.7, maxWidth: 340 }}>
                  Enter a verified contract address from Arc Testnet. Source code is fetched from{" "}
                  <a href="https://testnet.arcscan.app" target="_blank" rel="noreferrer"
                    style={{ color: "#60A5FA", textDecoration: "none" }}>testnet.arcscan.app</a>{" "}
                  and audited automatically.
                </div>
              </div>

              {/* Address input */}
              <div style={{ width: "100%", maxWidth: 440 }}>
                <div style={{ fontSize: 9, letterSpacing: "2px", color: "rgba(255,255,255,0.25)", marginBottom: 8 }}>
                  CONTRACT ADDRESS (Arc Testnet)
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <input
                    value={addressInput}
                    onChange={e => { setAddressInput(e.target.value); setFetchError(null); }}
                    onKeyDown={e => e.key === "Enter" && handleAddressFetch()}
                    placeholder="0x1234...abcd"
                    style={{
                      flex: 1, background: "#0D1117",
                      border: `1px solid ${fetchError ? "rgba(255,77,109,0.5)" : "rgba(255,255,255,0.1)"}`,
                      borderRadius: 3, color: "#E2E8F0", padding: "10px 14px",
                      fontSize: 13, fontFamily: "'Courier New', monospace", outline: "none",
                      letterSpacing: "0.5px",
                    }}
                  />
                  <button onClick={handleAddressFetch} disabled={fetching || !addressInput.trim()} style={{
                    padding: "10px 18px", borderRadius: 3, cursor: "pointer",
                    background: addressInput.trim() ? "rgba(96,165,250,0.1)" : "rgba(255,255,255,0.03)",
                    border: `1px solid ${addressInput.trim() ? "rgba(96,165,250,0.5)" : "rgba(255,255,255,0.07)"}`,
                    color: addressInput.trim() ? "#60A5FA" : "rgba(255,255,255,0.18)",
                    fontSize: 11, fontWeight: 800, letterSpacing: "1.5px",
                    fontFamily: "inherit", whiteSpace: "nowrap",
                  }}>
                    {fetching ? "FETCHING…" : "FETCH →"}
                  </button>
                </div>

                {/* Error */}
                {fetchError && (
                  <div style={{
                    marginTop: 10, padding: "10px 12px", borderRadius: 3,
                    background: "rgba(255,77,109,0.07)", border: "1px solid rgba(255,77,109,0.2)",
                    fontSize: 11, color: "#FF4D6D", lineHeight: 1.6,
                  }}>
                    ✕ {fetchError}
                  </div>
                )}

                {/* Info note */}
                <div style={{ marginTop: 12, fontSize: 10, color: "rgba(255,255,255,0.18)", lineHeight: 1.7 }}>
                  ℹ Only contracts verified on ArcScan can be fetched. To verify your contract, use Hardhat or Foundry with the Blockscout verifier at testnet.arcscan.app.
                </div>
              </div>

              {/* Example addresses note */}
              <div style={{
                width: "100%", maxWidth: 440, background: "rgba(0,229,160,0.03)",
                border: "1px solid rgba(0,229,160,0.1)", borderRadius: 4, padding: "12px 14px",
              }}>
                <div style={{ fontSize: 9, letterSpacing: "2px", color: "#00E5A0", marginBottom: 8 }}>HOW TO FIND CONTRACT ADDRESSES</div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", lineHeight: 1.8 }}>
                  1. Go to{" "}
                  <a href="https://testnet.arcscan.app" target="_blank" rel="noreferrer" style={{ color: "#60A5FA", textDecoration: "none" }}>
                    testnet.arcscan.app
                  </a><br />
                  2. Search your contract address<br />
                  3. If verified, paste the address here → auto-fetch + audit
                </div>
              </div>
            </div>
          )}

          {/* Paste Code Mode */}
          {inputMode === "paste" && (
            <>
              <div style={{
                padding: "7px 16px", borderBottom: "1px solid rgba(255,255,255,0.04)",
                fontSize: 9, color: "rgba(255,255,255,0.2)", letterSpacing: "2px",
                display: "flex", justifyContent: "space-between", alignItems: "center",
              }}>
                <span>
                  SOLIDITY SOURCE
                  {fetchedMeta && (
                    <span style={{ marginLeft: 10, color: "#60A5FA" }}>
                      ↳ {fetchedMeta.name} · {fetchedMeta.address.slice(0, 8)}…{fetchedMeta.address.slice(-6)}
                    </span>
                  )}
                </span>
                {code && <span>{codeLines.length} lines</span>}
              </div>

              {!code ? (
                <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, padding: 40, textAlign: "center" }}>
                  <div style={{ fontSize: 28 }}>⬡</div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: "rgba(255,255,255,0.6)" }}>Paste your Solidity contract</div>
                  <div style={{ fontSize: 12, color: "rgba(255,255,255,0.25)", maxWidth: 320, lineHeight: 1.8 }}>
                    Or switch to <strong style={{ color: "#60A5FA" }}>Contract Address</strong> mode to auto-fetch from ArcScan.
                  </div>
                  <button onClick={() => { setCode(SAMPLE); reset(); }} style={{
                    padding: "8px 20px", borderRadius: 3, cursor: "pointer",
                    background: "rgba(0,229,160,0.08)", border: "1px solid rgba(0,229,160,0.28)",
                    color: "#00E5A0", fontSize: 11, letterSpacing: "2px", fontFamily: "inherit",
                  }}>TRY SAMPLE CONTRACT</button>
                </div>
              ) : (
                <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
                  <div style={{ position: "absolute", inset: 0, overflowY: "auto", display: "flex" }}>
                    {/* Gutter */}
                    <div style={{
                      minWidth: 48, background: "rgba(0,0,0,0.15)",
                      borderRight: "1px solid rgba(255,255,255,0.04)",
                      userSelect: "none", paddingTop: 12, flexShrink: 0,
                    }}>
                      {codeLines.map((_, i) => {
                        const ln = i + 1;
                        const f = findings.find(f => f.line === ln);
                        const sc = f ? SEV[f.rule.severity] : null;
                        return (
                          <div key={i} onClick={() => f && selectIssue(f)} style={{
                            height: 20, display: "flex", alignItems: "center", justifyContent: "flex-end",
                            paddingRight: 10, cursor: f ? "pointer" : "default",
                            background: selected?.line === ln && f ? sc.bg : "transparent",
                          }}>
                            {f
                              ? <span style={{ fontSize: 10, color: sc.color, fontWeight: 800 }}>{sc.icon}</span>
                              : <span style={{ fontSize: 10, color: "rgba(255,255,255,0.18)" }}>{ln}</span>
                            }
                          </div>
                        );
                      })}
                    </div>
                    <textarea
                      value={code}
                      onChange={e => { setCode(e.target.value); reset(); setFetchedMeta(null); }}
                      style={{
                        flex: 1, background: "transparent", border: "none", outline: "none",
                        color: "rgba(220,230,240,0.8)", fontSize: 12, lineHeight: "20px",
                        fontFamily: "'Courier New', monospace", resize: "none",
                        padding: "12px 16px", tabSize: 2, caretColor: "#00E5A0",
                      }}
                      spellCheck={false}
                    />
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* ── RESULTS PANEL ── */}
        <div style={{
          width: scanned ? 320 : 0, flexShrink: 0, overflow: "hidden",
          transition: "width 0.4s cubic-bezier(0.16,1,0.3,1)",
          display: "flex", flexDirection: "column",
          borderRight: scanned ? "1px solid rgba(255,255,255,0.05)" : "none",
        }}>
          {scanned && <>
            <div style={{
              padding: "7px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)",
              fontSize: 9, color: "rgba(255,255,255,0.2)", letterSpacing: "2px",
              display: "flex", justifyContent: "space-between",
            }}>
              <span>ISSUES ({findings.length})</span>
              <span style={{ color: critCount > 0 ? "#FF4D6D" : "#00E5A0" }}>
                {critCount > 0 ? `${critCount} CRITICAL` : "✓ SAFE"}
              </span>
            </div>

            {/* Score */}
            <div style={{
              padding: "14px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)",
              display: "flex", alignItems: "center", gap: 14,
            }}>
              <ScoreRing score={score} critical={critCount} />
              <div>
                <div style={{ fontSize: 10, color: "rgba(255,255,255,0.25)", marginBottom: 5, letterSpacing: "1px" }}>ARC COMPATIBILITY</div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {critCount > 0 && <span style={{ fontSize: 10, color: SEV.critical.color }}>✕ {critCount} critical</span>}
                  {warnCount > 0 && <span style={{ fontSize: 10, color: SEV.warning.color }}>⚠ {warnCount} warn</span>}
                  {infoCount > 0 && <span style={{ fontSize: 10, color: SEV.info.color }}>i {infoCount} info</span>}
                  {findings.length === 0 && <span style={{ fontSize: 10, color: "#00E5A0" }}>✓ No issues</span>}
                </div>
                <div style={{ fontSize: 9, color: "rgba(255,255,255,0.18)", marginTop: 4 }}>Click issue → AI fix</div>
              </div>
            </div>

            <div style={{ flex: 1, overflowY: "auto", padding: "10px 12px" }}>
              {findings.length === 0 ? (
                <div style={{ textAlign: "center", padding: 24 }}>
                  <div style={{ fontSize: 24, color: "#00E5A0", marginBottom: 8 }}>✓</div>
                  <div style={{ fontSize: 12, color: "#00E5A0", fontWeight: 700 }}>Arc-compatible</div>
                  <div style={{ fontSize: 10, color: "rgba(255,255,255,0.25)", marginTop: 4 }}>No known issues detected</div>
                </div>
              ) : findings.map(f => {
                const sc = SEV[f.rule.severity];
                const isActive = selected?.ruleId === f.ruleId && selected?.line === f.line;
                return (
                  <div key={`${f.ruleId}-${f.line}`} onClick={() => selectIssue(f)} style={{
                    border: `1px solid ${isActive ? sc.color : sc.border}`,
                    borderLeft: `3px solid ${sc.color}`,
                    borderRadius: 4, padding: "10px 11px", marginBottom: 6,
                    cursor: "pointer", background: isActive ? sc.bg : "rgba(255,255,255,0.015)",
                    transition: "all 0.15s",
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                      <span style={{ fontSize: 9, color: sc.color, fontWeight: 800, letterSpacing: "1.5px" }}>{sc.icon} {sc.label}</span>
                      <span style={{ fontSize: 9, color: "rgba(255,255,255,0.22)" }}>L{f.line}</span>
                    </div>
                    <div style={{ fontSize: 12, fontWeight: 800, color: "#F1F5F9", marginBottom: 3 }}>{f.rule.title}</div>
                    <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", fontFamily: "inherit" }}>
                      {f.lineContent.slice(0, 42)}{f.lineContent.length > 42 ? "…" : ""}
                    </div>
                  </div>
                );
              })}
            </div>
          </>}
        </div>

        {/* ── DETAIL PANEL ── */}
        <div style={{
          width: selected ? 360 : 0, flexShrink: 0,
          overflow: "hidden", transition: "width 0.35s cubic-bezier(0.16,1,0.3,1)",
          display: "flex", flexDirection: "column",
        }}>
          {selected && (() => {
            const sc = SEV[selected.rule.severity];
            const ai = selKey ? aiText[selKey] : null;
            return <>
              <div style={{
                padding: "7px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)",
                fontSize: 9, color: "rgba(255,255,255,0.2)", letterSpacing: "2px",
                display: "flex", justifyContent: "space-between", alignItems: "center",
              }}>
                <span>ISSUE DETAIL</span>
                <button onClick={() => setSelected(null)} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.25)", cursor: "pointer", fontSize: 14, padding: 0 }}>✕</button>
              </div>
              <div style={{ flex: 1, overflowY: "auto", padding: "16px 14px" }}>
                <div style={{
                  display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 10px",
                  borderRadius: 3, background: sc.bg, border: `1px solid ${sc.border}`, marginBottom: 12,
                }}>
                  <span style={{ color: sc.color, fontSize: 11, fontWeight: 900 }}>{sc.icon}</span>
                  <span style={{ color: sc.color, fontSize: 9, letterSpacing: "2px", fontWeight: 800 }}>{sc.label}</span>
                  <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 9 }}>LINE {selected.line}</span>
                </div>
                <div style={{ fontSize: 15, fontWeight: 900, color: "#F1F5F9", marginBottom: 4, fontFamily: "'Georgia', serif", lineHeight: 1.3 }}>
                  {selected.rule.title}
                </div>
                <div style={{ fontSize: 11, color: sc.color, marginBottom: 16, letterSpacing: "0.5px" }}>{selected.rule.short}</div>

                <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: 4, border: `1px solid ${sc.border}`, padding: "10px 12px", marginBottom: 14 }}>
                  <div style={{ fontSize: 8, letterSpacing: "2px", color: "rgba(255,255,255,0.2)", marginBottom: 6 }}>FLAGGED CODE</div>
                  <code style={{ fontSize: 11, color: sc.color, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                    {selected.lineContent}
                  </code>
                </div>

                <div style={{ background: "rgba(0,229,160,0.03)", border: "1px solid rgba(0,229,160,0.1)", borderRadius: 4, padding: "12px", marginBottom: 14 }}>
                  <div style={{ fontSize: 8, letterSpacing: "2px", color: "#00E5A0", marginBottom: 8 }}>
                    ⬡ AI ANALYSIS {aiLoading ? "— LOADING…" : ""}
                  </div>
                  {aiLoading ? (
                    <div style={{ display: "flex", gap: 5 }}>
                      {[0,1,2].map(i => (
                        <div key={i} style={{ width: 5, height: 5, borderRadius: "50%", background: "#00E5A0", animation: `pulse ${0.8}s ${i * 0.2}s infinite` }} />
                      ))}
                    </div>
                  ) : (
                    <p style={{ fontSize: 12, color: "rgba(226,232,240,0.65)", lineHeight: 1.75, margin: 0, fontFamily: "'Georgia', serif" }}>
                      {ai || selected.rule.description}
                    </p>
                  )}
                </div>

                <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 4, padding: "12px", marginBottom: 14 }}>
                  <div style={{ fontSize: 8, letterSpacing: "2px", color: "rgba(255,255,255,0.25)", marginBottom: 8 }}>RECOMMENDED FIX</div>
                  <p style={{ fontSize: 12, color: "rgba(226,232,240,0.6)", margin: 0, lineHeight: 1.7 }}>{selected.rule.fix}</p>
                </div>

                <a href={selected.rule.docs} target="_blank" rel="noreferrer" style={{
                  display: "flex", alignItems: "center", gap: 5,
                  fontSize: 10, color: "rgba(255,255,255,0.2)", textDecoration: "none", letterSpacing: "1px",
                }}>↗ Arc Docs Reference</a>
              </div>
            </>;
          })()}
        </div>
      </div>

      {/* FOOTER */}
      <div style={{
        borderTop: "1px solid rgba(255,255,255,0.04)", padding: "7px 16px",
        display: "flex", gap: 6, flexWrap: "wrap", background: "rgba(7,9,14,0.95)", flexShrink: 0,
      }}>
        {RULES.map(r => (
          <span key={r.id} style={{
            fontSize: 9, padding: "2px 7px", borderRadius: 2, letterSpacing: "0.5px",
            color: SEV[r.severity].dim, border: `1px solid ${SEV[r.severity].border}`,
          }}>{r.short}</span>
        ))}
      </div>

      <style>{`
        @keyframes sweep { 0%{transform:translateX(-100%)} 100%{transform:translateX(200%)} }
        @keyframes pulse { 0%,100%{opacity:0.2;transform:scale(0.8)} 50%{opacity:1;transform:scale(1.2)} }
        textarea::placeholder { color: rgba(255,255,255,0.1); }
        ::-webkit-scrollbar { width: 3px; height: 3px; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 2px; }
        ::-webkit-scrollbar-track { background: transparent; }
      `}</style>
    </div>
  );
}
