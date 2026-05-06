import { useState, useEffect, useRef } from "react";

const RULES = [
  { id: "prevrandao", pattern: /block\.prevrandao|PREV_RANDAO/g, severity: "critical", title: "Randomness always returns 0", short: "block.prevrandao = 0", description: "Arc sets block.prevrandao to 0 permanently. Any contract using this for randomness is instantly exploitable.", fix: "Use Chainlink VRF or another onchain oracle for randomness on Arc.", docs: "https://docs.arc.network/arc/references/evm-compatibility" },
  { id: "selfdestruct", pattern: /selfdestruct\s*\(/g, severity: "critical", title: "SELFDESTRUCT restricted on Arc", short: "selfdestruct() reverts", description: "Arc blocks SELFDESTRUCT during deployment to prevent USDC burns.", fix: "Replace with a withdrawal + pause pattern.", docs: "https://docs.arc.network/arc/references/evm-compatibility" },
  { id: "eth-value", pattern: /\d+\s*(ether|gwei|wei)\b|\bmsg\.value\b/g, severity: "warning", title: "ETH denomination detected", short: "Gas is USDC, not ETH", description: "Arc uses USDC as native gas. ETH denominations behave incorrectly.", fix: "Use USDC denominations. 1e6 for ERC-20, 1e18 for native.", docs: "https://docs.arc.network/arc/concepts/stable-fee-design" },
  { id: "blob", pattern: /blobhash\s*\(|EIP.?4844|blob_base_fee/gi, severity: "warning", title: "EIP-4844 blobs disabled", short: "Blob txns not supported", description: "Arc does not support EIP-4844 blob transactions.", fix: "Use standard calldata instead.", docs: "https://docs.arc.network/arc/references/evm-compatibility" },
  { id: "timestamp", pattern: /block\.timestamp\s*[<>]=?\s*|[<>]=?\s*block\.timestamp/g, severity: "warning", title: "Timestamp ordering unsafe", short: "Blocks share timestamps", description: "Arc sub-second blocks can share the same wall-clock timestamp.", fix: "Use block numbers for ordering, or add tolerance buffers.", docs: "https://docs.arc.network/arc/references/evm-compatibility" },
  { id: "transfer-send", pattern: /\.transfer\s*\(|\.send\s*\(/g, severity: "warning", title: "ETH transfer pattern", short: ".transfer()/.send() check intent", description: "Gas stipends differ from Ethereum. Ensure you intend native USDC.", fix: "Use IERC20(USDC_ADDRESS).transfer() for ERC-20 USDC explicitly.", docs: "https://docs.arc.network/arc/references/contract-addresses" },
  { id: "decimal", pattern: /10\s*\*\*\s*18|1e18|\bdecimals\(\)/gi, severity: "info", title: "USDC decimal mismatch risk", short: "Native=18dec, ERC-20=6dec", description: "Native USDC uses 18 decimals, ERC-20 uses 6. Mixing causes 1e12x amount errors.", fix: "Use 1e6 for ERC-20 USDC, 1e18 for native. Never assume.", docs: "https://docs.arc.network/arc/references/evm-compatibility#erc20-interface" },
  { id: "blockhash", pattern: /blockhash\s*\(|block\.difficulty/g, severity: "info", title: "Weak randomness source", short: "blockhash exploitable", description: "Weak randomness, worse on Arc with permissioned validators.", fix: "Use Chainlink VRF or commit-reveal schemes.", docs: "https://docs.arc.network/arc/references/evm-compatibility" },
];

const SEV = {
  critical: { color: "#FF3B6B", bg: "rgba(255,59,107,0.06)", border: "rgba(255,59,107,0.2)", icon: "✕", label: "CRITICAL", glow: "rgba(255,59,107,0.5)" },
  warning:  { color: "#FFB340", bg: "rgba(255,179,64,0.06)",  border: "rgba(255,179,64,0.2)",  icon: "⚠", label: "WARNING",  glow: "rgba(255,179,64,0.5)" },
  info:     { color: "#5E9FFF", bg: "rgba(94,159,255,0.06)",  border: "rgba(94,159,255,0.2)",  icon: "i", label: "INFO",     glow: "rgba(94,159,255,0.5)" },
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

    // WARNING: ETH denomination
    function deposit() external payable {
        require(msg.value >= 0.01 ether, "min 0.01 ETH");
        balances[msg.sender] += msg.value;
    }

    // WARNING: Timestamp ordering unsafe
    function isExpired(uint256 deadline) public view returns (bool) {
        return block.timestamp > deadline;
    }

    // INFO: decimal mismatch
    function toUSDC(uint256 amount) public pure returns (uint256) {
        return amount * 1e18;
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
      if (!results.find(r => r.ruleId === rule.id && r.line === ln))
        results.push({ ruleId: rule.id, rule, line: ln, lineContent: (lines[ln - 1] || "").trim() });
    }
  });
  return results.sort((a, b) => ({ critical: 0, warning: 1, info: 2 }[a.rule.severity] - { critical: 0, warning: 1, info: 2 }[b.rule.severity] || a.line - b.line));
}

async function fetchContract(address) {
  const res = await fetch(`https://testnet.arcscan.app/api/v2/smart-contracts/${address}`);
  if (!res.ok) throw new Error(`ArcScan returned ${res.status}`);
  const data = await res.json();
  if (data.source_code) return { code: data.source_code, name: data.name || "Contract" };
  if (data.additional_sources?.length > 0) return { code: data.additional_sources.map(s => `// ${s.file_path}\n${s.source_code}`).join("\n\n"), name: data.name || "Contract" };
  throw new Error("Contract not verified on ArcScan.");
}

async function getAI(finding, code) {
  const lines = code.split("\n");
  const snippet = lines.slice(Math.max(0, finding.line - 3), finding.line + 2).join("\n");
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: 1000, messages: [{ role: "user", content: `Arc blockchain security expert. Issue: ${finding.rule.severity.toUpperCase()}: ${finding.rule.title}\nLine ${finding.line}: ${finding.lineContent}\nContext:\n\`\`\`solidity\n${snippet}\n\`\`\`\nArc reason: ${finding.rule.description}\n\n2-3 sentences: what breaks + exact fix. Direct, no preamble.` }] }),
  });
  const d = await res.json();
  return d.content?.[0]?.text || finding.rule.description;
}

// ─── FULL SPACE SCENE CANVAS ──────────────────────────────────────────────────
function SpaceScene() {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let animId, t = 0;

    const resize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    resize();
    window.addEventListener("resize", resize);

    // ── Seed random for stable asteroid shapes ────────────────────────────────
    let seed = 42;
    const rng = () => { seed = (seed * 9301 + 49297) % 233280; return seed / 233280; };

    // ── Stars ─────────────────────────────────────────────────────────────────
    const makeStars = (n, minR, maxR) => Array.from({ length: n }, () => ({
      x: Math.random(), y: Math.random(),
      r: minR + Math.random() * (maxR - minR),
      phase: Math.random() * Math.PI * 2,
      speed: 0.3 + Math.random() * 1.2,
      hue: Math.random() < 0.15 ? 220 : Math.random() < 0.1 ? 40 : 0,
    }));
    const stars = { far: makeStars(280, 0.25, 0.6), mid: makeStars(90, 0.6, 1.1), near: makeStars(35, 1.1, 1.9) };

    // ── Milky Way stars ───────────────────────────────────────────────────────
    const milkyStars = Array.from({ length: 700 }, () => {
      const along = Math.random();
      const perp = (Math.random() - 0.5) * (0.08 + 0.12 * Math.sin(along * Math.PI));
      return {
        x: along - perp * 0.5,
        y: (1 - along) + perp,
        r: 0.15 + Math.random() * 0.7,
        a: 0.15 + Math.random() * 0.6,
        hue: 200 + Math.random() * 60,
      };
    });

    // ── Asteroids ─────────────────────────────────────────────────────────────
    const makeAsteroid = (i) => {
      const sides = 7 + Math.floor(rng() * 4);
      const vertices = Array.from({ length: sides }, (_, j) => {
        const angle = (j / sides) * Math.PI * 2;
        const r = 0.65 + rng() * 0.35;
        return { cos: Math.cos(angle) * r, sin: Math.sin(angle) * r };
      });
      const size = 14 + rng() * 38;
      const speed = 0.04 + rng() * 0.12;
      const angle = rng() * Math.PI * 2;
      return {
        x: rng(), y: rng(),
        vx: Math.cos(angle) * speed * 0.0008,
        vy: Math.sin(angle) * speed * 0.0008,
        rot: rng() * Math.PI * 2,
        rotSpeed: (rng() - 0.5) * 0.004,
        size, vertices,
        shade: Math.floor(55 + rng() * 45),
        rimBrightness: 0.3 + rng() * 0.4,
        lightAngle: rng() * Math.PI * 2,
      };
    };
    const asteroids = Array.from({ length: 9 }, (_, i) => makeAsteroid(i));

    // ── Shooting stars ────────────────────────────────────────────────────────
    const shoots = Array.from({ length: 4 }, () => ({
      active: false, x: 0, y: 0, vx: 0, vy: 0, len: 0, life: 0, maxLife: 0,
      timer: Math.floor(Math.random() * 300 + 100),
    }));

    // ── Planet (bottom-right) ─────────────────────────────────────────────────
    const planet = { rx: 0.88, ry: 0.82, r: 64, hue: 260, phase: 0 };

    // ── Draw asteroid ─────────────────────────────────────────────────────────
    const drawAsteroid = (a, W, H) => {
      const px = a.x * W, py = a.y * H;
      ctx.save();
      ctx.translate(px, py);
      ctx.rotate(a.rot);

      // Main body
      ctx.beginPath();
      a.vertices.forEach((v, i) => {
        const x = v.cos * a.size, y = v.sin * a.size;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.closePath();

      // Rock gradient
      const grad = ctx.createRadialGradient(
        Math.cos(a.lightAngle) * a.size * 0.3,
        Math.sin(a.lightAngle) * a.size * 0.3,
        0, 0, 0, a.size
      );
      grad.addColorStop(0, `rgba(${a.shade + 40},${a.shade + 35},${a.shade + 30},0.9)`);
      grad.addColorStop(0.5, `rgba(${a.shade},${a.shade - 5},${a.shade - 10},0.85)`);
      grad.addColorStop(1, `rgba(${a.shade - 20},${a.shade - 25},${a.shade - 20},0.8)`);
      ctx.fillStyle = grad;
      ctx.fill();

      // Rim light
      ctx.beginPath();
      a.vertices.forEach((v, i) => {
        const x = v.cos * a.size, y = v.sin * a.size;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.closePath();
      ctx.strokeStyle = `rgba(180,175,200,${a.rimBrightness * 0.4})`;
      ctx.lineWidth = 1.2;
      ctx.stroke();

      // Crater
      const cx2 = Math.cos(a.lightAngle + 1.2) * a.size * 0.25;
      const cy2 = Math.sin(a.lightAngle + 1.2) * a.size * 0.25;
      ctx.beginPath();
      ctx.arc(cx2, cy2, a.size * 0.15, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(0,0,0,0.35)`;
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.restore();
    };

    // ── Draw planet ───────────────────────────────────────────────────────────
    const drawPlanet = (W, H) => {
      const px = planet.rx * W, py = planet.ry * H;
      const r = planet.r;

      // Outer glow
      const outerGlow = ctx.createRadialGradient(px, py, r * 0.6, px, py, r * 2.2);
      outerGlow.addColorStop(0, `hsla(${planet.hue},70%,60%,0.12)`);
      outerGlow.addColorStop(0.5, `hsla(${planet.hue},70%,50%,0.05)`);
      outerGlow.addColorStop(1, "transparent");
      ctx.beginPath();
      ctx.arc(px, py, r * 2.2, 0, Math.PI * 2);
      ctx.fillStyle = outerGlow;
      ctx.fill();

      // Planet body
      const bodyGrad = ctx.createRadialGradient(px - r * 0.3, py - r * 0.3, 0, px, py, r);
      bodyGrad.addColorStop(0, `hsla(${planet.hue + 30},60%,55%,0.95)`);
      bodyGrad.addColorStop(0.4, `hsla(${planet.hue},65%,40%,0.9)`);
      bodyGrad.addColorStop(0.8, `hsla(${planet.hue - 20},70%,25%,0.95)`);
      bodyGrad.addColorStop(1, `hsla(${planet.hue - 30},80%,15%,1)`);
      ctx.beginPath();
      ctx.arc(px, py, r, 0, Math.PI * 2);
      ctx.fillStyle = bodyGrad;
      ctx.fill();

      // Atmosphere ring
      ctx.beginPath();
      ctx.arc(px, py, r + 4, 0, Math.PI * 2);
      ctx.strokeStyle = `hsla(${planet.hue + 40},80%,75%,0.25)`;
      ctx.lineWidth = 3;
      ctx.stroke();

      // Cloud bands
      ctx.save();
      ctx.beginPath();
      ctx.arc(px, py, r, 0, Math.PI * 2);
      ctx.clip();
      for (let band = 0; band < 3; band++) {
        const by = py - r * 0.5 + band * r * 0.4 + Math.sin(t * 0.2 + band) * 3;
        const bGrad = ctx.createLinearGradient(px - r, by, px + r, by);
        bGrad.addColorStop(0, "transparent");
        bGrad.addColorStop(0.3, `hsla(${planet.hue + 20},50%,70%,0.06)`);
        bGrad.addColorStop(0.7, `hsla(${planet.hue + 20},50%,70%,0.06)`);
        bGrad.addColorStop(1, "transparent");
        ctx.fillStyle = bGrad;
        ctx.fillRect(px - r, by - 6, r * 2, 12);
      }
      ctx.restore();

      // Shadow
      const shadow = ctx.createRadialGradient(px + r * 0.4, py + r * 0.1, 0, px, py, r);
      shadow.addColorStop(0, "transparent");
      shadow.addColorStop(0.6, "transparent");
      shadow.addColorStop(1, "rgba(0,0,15,0.7)");
      ctx.beginPath();
      ctx.arc(px, py, r, 0, Math.PI * 2);
      ctx.fillStyle = shadow;
      ctx.fill();
    };

    // ── Main draw loop ────────────────────────────────────────────────────────
    const draw = () => {
      t += 0.008;
      const W = canvas.width, H = canvas.height;
      ctx.clearRect(0, 0, W, H);

      // Deep space gradient background
      const bg = ctx.createLinearGradient(0, 0, W * 0.5, H);
      bg.addColorStop(0,   "#01000A");
      bg.addColorStop(0.3, "#020010");
      bg.addColorStop(0.6, "#010008");
      bg.addColorStop(1,   "#000508");
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, W, H);

      // ── Milky Way band ──────────────────────────────────────────────────────
      // Glow
      const mwGlow = ctx.createLinearGradient(0, H, W, 0);
      mwGlow.addColorStop(0,   "rgba(80,60,140,0)");
      mwGlow.addColorStop(0.3, "rgba(80,60,140,0.06)");
      mwGlow.addColorStop(0.5, "rgba(100,80,180,0.10)");
      mwGlow.addColorStop(0.7, "rgba(60,80,160,0.06)");
      mwGlow.addColorStop(1,   "rgba(40,60,120,0)");
      ctx.fillStyle = mwGlow;
      ctx.fillRect(0, 0, W, H);

      // Stars in milky way
      milkyStars.forEach(s => {
        const sx = s.x * W, sy = s.y * H;
        if (sx < -10 || sx > W + 10 || sy < -10 || sy > H + 10) return;
        ctx.beginPath();
        ctx.arc(sx, sy, s.r, 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${s.hue},60%,95%,${s.a})`;
        ctx.fill();
      });

      // ── Far stars ──────────────────────────────────────────────────────────
      stars.far.forEach(s => {
        const a = 0.25 + 0.35 * Math.abs(Math.sin(t * s.speed + s.phase));
        ctx.beginPath();
        ctx.arc(s.x * W, s.y * H, s.r, 0, Math.PI * 2);
        ctx.fillStyle = s.hue === 220 ? `rgba(200,210,255,${a})` : s.hue === 40 ? `rgba(255,245,200,${a})` : `rgba(255,255,255,${a})`;
        ctx.fill();
      });

      // ── Mid stars ──────────────────────────────────────────────────────────
      stars.mid.forEach(s => {
        const a = 0.4 + 0.4 * Math.abs(Math.sin(t * s.speed * 0.7 + s.phase));
        ctx.beginPath();
        ctx.arc(s.x * W, s.y * H, s.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,255,255,${a * 0.85})`;
        ctx.fill();
      });

      // ── Near stars (with cross-sparkle) ────────────────────────────────────
      stars.near.forEach(s => {
        const a = 0.5 + 0.5 * Math.abs(Math.sin(t * s.speed * 0.5 + s.phase));
        const sx = s.x * W, sy = s.y * H;
        ctx.beginPath();
        ctx.arc(sx, sy, s.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,255,255,${a})`;
        ctx.fill();
        // Sparkle cross
        if (a > 0.8) {
          ctx.strokeStyle = `rgba(255,255,255,${(a - 0.8) * 3})`;
          ctx.lineWidth = 0.5;
          ctx.beginPath(); ctx.moveTo(sx - s.r * 3, sy); ctx.lineTo(sx + s.r * 3, sy); ctx.stroke();
          ctx.beginPath(); ctx.moveTo(sx, sy - s.r * 3); ctx.lineTo(sx, sy + s.r * 3); ctx.stroke();
        }
      });

      // ── Nebula blobs ────────────────────────────────────────────────────────
      const nebulas = [
        { x: 0.15, y: 0.25, r: W * 0.22, h: 260, a: 0.07 },
        { x: 0.75, y: 0.15, r: W * 0.18, h: 190, a: 0.06 },
        { x: 0.5,  y: 0.6,  r: W * 0.15, h: 310, a: 0.05 },
        { x: 0.85, y: 0.5,  r: W * 0.12, h: 340, a: 0.06 },
      ];
      nebulas.forEach(n => {
        const nx = n.x * W, ny = n.y * H;
        const grad = ctx.createRadialGradient(nx, ny, 0, nx, ny, n.r);
        grad.addColorStop(0, `hsla(${n.h},70%,55%,${n.a})`);
        grad.addColorStop(0.5, `hsla(${n.h},60%,40%,${n.a * 0.4})`);
        grad.addColorStop(1, "transparent");
        ctx.beginPath();
        ctx.arc(nx, ny, n.r, 0, Math.PI * 2);
        ctx.fillStyle = grad;
        ctx.fill();
      });

      // ── Planet ──────────────────────────────────────────────────────────────
      planet.phase += 0.001;
      planet.hue = 255 + Math.sin(planet.phase) * 15;
      drawPlanet(W, H);

      // ── Asteroids ───────────────────────────────────────────────────────────
      asteroids.forEach(a => {
        a.x += a.vx;
        a.y += a.vy;
        a.rot += a.rotSpeed;
        if (a.x < -0.1) a.x = 1.1;
        if (a.x > 1.1)  a.x = -0.1;
        if (a.y < -0.1) a.y = 1.1;
        if (a.y > 1.1)  a.y = -0.1;
        drawAsteroid(a, W, H);
      });

      // ── Shooting stars ──────────────────────────────────────────────────────
      shoots.forEach(s => {
        s.timer--;
        if (s.timer <= 0 && !s.active) {
          s.active = true;
          s.x = Math.random() * W * 0.8;
          s.y = Math.random() * H * 0.4;
          const ang = Math.PI * 0.2 + Math.random() * 0.3;
          const spd = 10 + Math.random() * 8;
          s.vx = Math.cos(ang) * spd;
          s.vy = Math.sin(ang) * spd;
          s.len = 60 + Math.random() * 80;
          s.life = 0;
          s.maxLife = s.len / spd * 1.8;
        }
        if (s.active) {
          s.life++;
          const tail = Math.max(0, 1 - s.life / s.maxLife);
          const ex = s.x + s.vx * s.life;
          const ey = s.y + s.vy * s.life;
          const sx2 = ex - s.vx * (s.len / (s.vx * s.vx + s.vy * s.vy) ** 0.5) * tail;
          const sy2 = ey - s.vy * (s.len / (s.vx * s.vx + s.vy * s.vy) ** 0.5) * tail;
          const grad = ctx.createLinearGradient(sx2, sy2, ex, ey);
          grad.addColorStop(0, "rgba(255,255,255,0)");
          grad.addColorStop(0.6, "rgba(180,160,255,0.5)");
          grad.addColorStop(1, `rgba(255,255,255,${tail * 0.9})`);
          ctx.beginPath(); ctx.moveTo(sx2, sy2); ctx.lineTo(ex, ey);
          ctx.strokeStyle = grad; ctx.lineWidth = 1.5; ctx.stroke();
          if (s.life >= s.maxLife) { s.active = false; s.timer = 200 + Math.floor(Math.random() * 300); }
        }
      });

      animId = requestAnimationFrame(draw);
    };

    draw();
    return () => { cancelAnimationFrame(animId); window.removeEventListener("resize", resize); };
  }, []);

  return <canvas ref={canvasRef} style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0 }} />;
}

// ─── UI COMPONENTS ────────────────────────────────────────────────────────────
function HoloText({ children, size = 13, style = {} }) {
  return (
    <span style={{ fontSize: size, fontWeight: 900, background: "linear-gradient(90deg,#06B6D4,#8B5CF6,#EC4899,#06B6D4)", backgroundSize: "300% 100%", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", animation: "holoShift 4s linear infinite", ...style }}>
      {children}
    </span>
  );
}

function Glass({ children, style = {}, glow, glowColor = "rgba(124,58,237,0.3)", onClick }) {
  const [hov, setHov] = useState(false);
  return (
    <div onClick={onClick} onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)} style={{ background: hov ? "rgba(255,255,255,0.055)" : "rgba(255,255,255,0.028)", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 12, transition: "all 0.25s", boxShadow: glow ? `0 0 28px ${glowColor}, inset 0 1px 0 rgba(255,255,255,0.08)` : "inset 0 1px 0 rgba(255,255,255,0.05)", ...style }}>
      {children}
    </div>
  );
}

function ScoreRing({ score, critical }) {
  const color = critical > 0 ? "#FF3B6B" : score >= 80 ? "#06B6D4" : "#FFB340";
  const r = 30, c = 2 * Math.PI * r, dash = (score / 100) * c;
  return (
    <div style={{ position: "relative", width: 80, height: 80, flexShrink: 0 }}>
      <svg width={80} height={80} style={{ transform: "rotate(-90deg)", filter: `drop-shadow(0 0 10px ${color})` }}>
        <circle cx={40} cy={40} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={5} />
        <circle cx={40} cy={40} r={r} fill="none" stroke={color} strokeWidth={5} strokeDasharray={`${dash} ${c}`} strokeLinecap="round" style={{ transition: "stroke-dasharray 1.2s cubic-bezier(0.16,1,0.3,1)" }} />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <div style={{ fontSize: 20, fontWeight: 900, color, fontFamily: "'Georgia',serif", lineHeight: 1, textShadow: `0 0 15px ${color}` }}>{score}</div>
        <div style={{ fontSize: 8, color: "rgba(255,255,255,0.3)", letterSpacing: 1 }}>/100</div>
      </div>
    </div>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
export default function ArcAuditor() {
  const [inputMode, setInputMode] = useState("paste");
  const [code, setCode] = useState("");
  const [addressInput, setAddressInput] = useState("");
  const [fetchedMeta, setFetchedMeta] = useState(null);
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

  const handleFetch = async () => {
    const addr = addressInput.trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) { setFetchError("Invalid address format."); return; }
    setFetching(true); setFetchError(null); reset();
    try { const r = await fetchContract(addr); setCode(r.code); setFetchedMeta({ name: r.name, address: addr }); setInputMode("paste"); }
    catch (e) { setFetchError(e.message); } finally { setFetching(false); }
  };

  const runScan = () => {
    if (!code.trim() || scanning) return;
    setScanning(true); setScanned(false); setFindings([]); setSelected(null);
    setTimeout(() => { setFindings(scanCode(code)); setScanning(false); setScanned(true); }, 1600);
  };

  const selectIssue = async (f) => {
    setSelected(f);
    const key = `${f.ruleId}-${f.line}`;
    if (!aiText[key]) {
      setAiLoading(true);
      const tx = await getAI(f, code).catch(() => f.rule.description);
      setAiText(p => ({ ...p, [key]: tx }));
      setAiLoading(false);
    }
  };

  const crit = findings.filter(f => f.rule.severity === "critical").length;
  const warn = findings.filter(f => f.rule.severity === "warning").length;
  const info = findings.filter(f => f.rule.severity === "info").length;
  const score = scanned ? Math.max(0, 100 - crit * 28 - warn * 10 - info * 4) : 0;
  const codeLines = code.split("\n");
  const selKey = selected ? `${selected.ruleId}-${selected.line}` : null;

  return (
    <div style={{ fontFamily: "'Courier New', monospace", background: "#01000A", minHeight: "100vh", color: "#E2E8F0", display: "flex", flexDirection: "column", opacity: loaded ? 1 : 0, transition: "opacity 0.8s", position: "relative" }}>
      <SpaceScene />

      {/* HEADER */}
      <header style={{ height: 60, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 24px", position: "sticky", top: 0, zIndex: 20, flexShrink: 0, background: "rgba(1,0,10,0.75)", backdropFilter: "blur(24px)", WebkitBackdropFilter: "blur(24px)", borderBottom: "1px solid rgba(255,255,255,0.06)", boxShadow: "0 1px 0 rgba(124,58,237,0.08), 0 8px 32px rgba(0,0,0,0.5)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, background: "linear-gradient(135deg,rgba(124,58,237,0.35),rgba(6,182,212,0.25))", border: "1px solid rgba(255,255,255,0.12)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, boxShadow: "0 0 20px rgba(124,58,237,0.45), inset 0 1px 0 rgba(255,255,255,0.15)" }}>⬡</div>
          <div>
            <HoloText size={14}>Arc Solidity Auditor</HoloText>
            <div style={{ fontSize: 9, color: "rgba(255,255,255,0.2)", letterSpacing: "2.5px", marginTop: 1 }}>ARC NETWORK · COMPATIBILITY SCANNER</div>
          </div>
        </div>

        <div style={{ display: "flex", background: "rgba(255,255,255,0.04)", borderRadius: 8, padding: 4, border: "1px solid rgba(255,255,255,0.06)", gap: 2 }}>
          {[{ id: "paste", label: "📋 Paste Code" }, { id: "address", label: "🔍 Address" }].map(({ id, label }) => (
            <button key={id} onClick={() => { setInputMode(id); reset(); }} style={{ padding: "5px 14px", borderRadius: 6, border: "none", cursor: "pointer", fontFamily: "inherit", background: inputMode === id ? "linear-gradient(135deg,rgba(124,58,237,0.45),rgba(6,182,212,0.3))" : "transparent", color: inputMode === id ? "#fff" : "rgba(255,255,255,0.3)", fontSize: 10, fontWeight: inputMode === id ? 700 : 400, boxShadow: inputMode === id ? "0 0 16px rgba(124,58,237,0.3), inset 0 1px 0 rgba(255,255,255,0.15)" : "none", transition: "all 0.2s" }}>{label}</button>
          ))}
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={() => { setCode(SAMPLE); setFetchedMeta(null); reset(); setInputMode("paste"); }} style={{ padding: "6px 14px", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, color: "rgba(255,255,255,0.35)", fontSize: 10, cursor: "pointer", fontFamily: "inherit", letterSpacing: "1px" }}>SAMPLE</button>
          <button onClick={runScan} disabled={!code.trim() || scanning} style={{ padding: "7px 20px", borderRadius: 8, cursor: code.trim() && !scanning ? "pointer" : "not-allowed", background: code.trim() && !scanning ? "linear-gradient(135deg,rgba(124,58,237,0.55),rgba(6,182,212,0.45))" : "rgba(255,255,255,0.04)", border: `1px solid ${code.trim() && !scanning ? "rgba(124,58,237,0.6)" : "rgba(255,255,255,0.07)"}`, color: code.trim() && !scanning ? "#fff" : "rgba(255,255,255,0.2)", fontSize: 10, fontWeight: 800, letterSpacing: "2px", fontFamily: "inherit", boxShadow: code.trim() && !scanning ? "0 0 20px rgba(124,58,237,0.4), inset 0 1px 0 rgba(255,255,255,0.2)" : "none", transition: "all 0.2s" }}>{scanning ? "SCANNING…" : "RUN AUDIT →"}</button>
        </div>
      </header>

      {/* SCAN BAR */}
      <div style={{ height: 2, flexShrink: 0, overflow: "hidden", position: "relative", zIndex: 10 }}>
        {scanning && <div style={{ height: "100%", background: "linear-gradient(90deg,transparent,#8B5CF6,#06B6D4,#EC4899,transparent)", animation: "sweep 1.4s ease-in-out infinite" }} />}
        {scanned && !scanning && <div style={{ height: "100%", width: "100%", background: crit > 0 ? "linear-gradient(90deg,#FF3B6B,#FF6B9D)" : "linear-gradient(90deg,#06B6D4,#8B5CF6)", boxShadow: crit > 0 ? "0 0 10px #FF3B6B" : "0 0 10px #06B6D4" }} />}
        {fetching && <div style={{ height: "100%", background: "linear-gradient(90deg,transparent,#06B6D4,transparent)", animation: "sweep 1.2s ease-in-out infinite" }} />}
      </div>

      {/* BODY */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden", minHeight: 0, position: "relative", zIndex: 1 }}>

        {/* EDITOR */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", borderRight: "1px solid rgba(255,255,255,0.04)", minWidth: 0 }}>
          <div style={{ padding: "8px 20px", borderBottom: "1px solid rgba(255,255,255,0.04)", fontSize: 9, color: "rgba(255,255,255,0.2)", letterSpacing: "2px", display: "flex", justifyContent: "space-between", background: "rgba(255,255,255,0.01)" }}>
            <span>SOLIDITY SOURCE {fetchedMeta && <span style={{ color: "#06B6D4" }}>↳ {fetchedMeta.name}</span>}</span>
            {code && <span>{codeLines.length} lines</span>}
          </div>

          {inputMode === "address" && (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 40, gap: 28 }}>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 56, marginBottom: 16, filter: "drop-shadow(0 0 20px rgba(6,182,212,0.7))" }}>🔍</div>
                <HoloText size={20} style={{ display: "block", marginBottom: 10 }}>Fetch from ArcScan</HoloText>
                <div style={{ fontSize: 13, color: "rgba(255,255,255,0.3)", lineHeight: 1.8, maxWidth: 340 }}>Enter a verified Arc Testnet contract address to auto-fetch and audit</div>
              </div>
              <Glass style={{ width: "100%", maxWidth: 460, padding: 24 }}>
                <div style={{ fontSize: 9, letterSpacing: "2px", color: "rgba(255,255,255,0.3)", marginBottom: 10 }}>CONTRACT ADDRESS</div>
                <div style={{ display: "flex", gap: 10 }}>
                  <input value={addressInput} onChange={e => { setAddressInput(e.target.value); setFetchError(null); }} onKeyDown={e => e.key === "Enter" && handleFetch()} placeholder="0x1234...abcd" style={{ flex: 1, background: "rgba(255,255,255,0.04)", border: `1px solid ${fetchError ? "rgba(255,59,107,0.4)" : "rgba(255,255,255,0.08)"}`, borderRadius: 8, color: "#E2E8F0", padding: "10px 14px", fontSize: 13, fontFamily: "inherit", outline: "none" }} />
                  <button onClick={handleFetch} disabled={fetching} style={{ padding: "10px 18px", borderRadius: 8, cursor: "pointer", background: "linear-gradient(135deg,rgba(6,182,212,0.3),rgba(124,58,237,0.3))", border: "1px solid rgba(6,182,212,0.3)", color: "#06B6D4", fontSize: 11, fontWeight: 800, letterSpacing: "1px", fontFamily: "inherit", boxShadow: "0 0 16px rgba(6,182,212,0.2)" }}>{fetching ? "…" : "FETCH →"}</button>
                </div>
                {fetchError && <div style={{ marginTop: 12, padding: "10px 12px", borderRadius: 8, background: "rgba(255,59,107,0.06)", border: "1px solid rgba(255,59,107,0.2)", fontSize: 11, color: "#FF3B6B" }}>✕ {fetchError}</div>}
                <div style={{ marginTop: 16, fontSize: 10, color: "rgba(255,255,255,0.25)", lineHeight: 1.8 }}>Only verified contracts on <a href="https://testnet.arcscan.app" target="_blank" rel="noreferrer" style={{ color: "#06B6D4", textDecoration: "none" }}>testnet.arcscan.app</a> can be fetched.</div>
              </Glass>
            </div>
          )}

          {inputMode === "paste" && !code && (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 24, padding: 40, textAlign: "center" }}>
              <div style={{ position: "relative" }}>
                <div style={{ fontSize: 72, filter: "drop-shadow(0 0 30px rgba(124,58,237,0.9))", animation: "breathe 3s ease-in-out infinite" }}>⬡</div>
                <div style={{ position: "absolute", inset: -24, borderRadius: "50%", background: "radial-gradient(circle,rgba(124,58,237,0.12) 0%,transparent 70%)", animation: "breathe 3s ease-in-out infinite" }} />
              </div>
              <div>
                <HoloText size={20} style={{ display: "block", marginBottom: 10 }}>Paste your Solidity contract</HoloText>
                <div style={{ fontSize: 13, color: "rgba(255,255,255,0.25)", maxWidth: 320, lineHeight: 1.8 }}>Or switch to <span style={{ color: "#06B6D4" }}>Address</span> mode to auto-fetch from ArcScan</div>
              </div>
              <button onClick={() => { setCode(SAMPLE); reset(); }} style={{ padding: "12px 28px", borderRadius: 10, cursor: "pointer", background: "linear-gradient(135deg,rgba(124,58,237,0.35),rgba(6,182,212,0.25))", border: "1px solid rgba(124,58,237,0.45)", color: "#fff", fontSize: 12, letterSpacing: "2px", fontFamily: "inherit", boxShadow: "0 0 24px rgba(124,58,237,0.35), inset 0 1px 0 rgba(255,255,255,0.1)", backdropFilter: "blur(10px)" }}>TRY SAMPLE CONTRACT</button>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, justifyContent: "center", maxWidth: 440 }}>
                {RULES.map(r => (<span key={r.id} style={{ fontSize: 9, padding: "3px 10px", borderRadius: 20, color: SEV[r.severity].color, border: `1px solid ${SEV[r.severity].border}`, background: SEV[r.severity].bg, backdropFilter: "blur(10px)" }}>{r.short}</span>))}
              </div>
            </div>
          )}

          {inputMode === "paste" && code && (
            <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
              <div style={{ position: "absolute", inset: 0, overflowY: "auto", display: "flex" }}>
                <div style={{ minWidth: 52, background: "rgba(255,255,255,0.01)", borderRight: "1px solid rgba(255,255,255,0.04)", userSelect: "none", paddingTop: 12, flexShrink: 0 }}>
                  {codeLines.map((_, i) => {
                    const ln = i + 1, f = findings.find(f => f.line === ln), sc = f ? SEV[f.rule.severity] : null;
                    return (
                      <div key={i} onClick={() => f && selectIssue(f)} style={{ height: 20, display: "flex", alignItems: "center", justifyContent: "flex-end", paddingRight: 12, cursor: f ? "pointer" : "default", background: selected?.line === ln && f ? sc.bg : "transparent" }}>
                        {f ? <span style={{ fontSize: 10, color: sc.color, fontWeight: 900, textShadow: `0 0 8px ${sc.glow}` }}>{sc.icon}</span> : <span style={{ fontSize: 10, color: "rgba(255,255,255,0.12)" }}>{ln}</span>}
                      </div>
                    );
                  })}
                </div>
                <textarea value={code} onChange={e => { setCode(e.target.value); reset(); setFetchedMeta(null); }} style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: "rgba(220,230,240,0.7)", fontSize: 12, lineHeight: "20px", fontFamily: "inherit", resize: "none", padding: "12px 16px", tabSize: 2, caretColor: "#8B5CF6" }} spellCheck={false} />
              </div>
            </div>
          )}
        </div>

        {/* RESULTS */}
        <div style={{ width: scanned ? 340 : 0, flexShrink: 0, overflow: "hidden", transition: "width 0.5s cubic-bezier(0.16,1,0.3,1)", display: "flex", flexDirection: "column", borderRight: "1px solid rgba(255,255,255,0.04)" }}>
          {scanned && <>
            <div style={{ padding: "8px 16px", borderBottom: "1px solid rgba(255,255,255,0.04)", fontSize: 9, letterSpacing: "2px", display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(255,255,255,0.01)" }}>
              <span style={{ color: "rgba(255,255,255,0.2)" }}>ISSUES ({findings.length})</span>
              <span style={{ color: crit > 0 ? "#FF3B6B" : "#06B6D4", textShadow: `0 0 10px ${crit > 0 ? "#FF3B6B" : "#06B6D4"}` }}>{crit > 0 ? `${crit} CRITICAL` : "✓ SAFE"}</span>
            </div>
            <div style={{ padding: 14, borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
              <Glass style={{ padding: "14px 16px", display: "flex", alignItems: "center", gap: 14 }}>
                <ScoreRing score={score} critical={crit} />
                <div>
                  <div style={{ fontSize: 9, color: "rgba(255,255,255,0.25)", letterSpacing: "1px", marginBottom: 6 }}>ARC COMPATIBILITY</div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 4 }}>
                    {crit > 0 && <span style={{ fontSize: 10, color: "#FF3B6B", textShadow: "0 0 8px #FF3B6B" }}>✕ {crit} critical</span>}
                    {warn > 0 && <span style={{ fontSize: 10, color: "#FFB340", textShadow: "0 0 8px #FFB340" }}>⚠ {warn} warn</span>}
                    {info > 0 && <span style={{ fontSize: 10, color: "#5E9FFF", textShadow: "0 0 8px #5E9FFF" }}>i {info} info</span>}
                    {findings.length === 0 && <span style={{ fontSize: 10, color: "#06B6D4" }}>✓ All clear</span>}
                  </div>
                  <div style={{ fontSize: 9, color: "rgba(255,255,255,0.15)" }}>Click any issue for AI fix →</div>
                </div>
              </Glass>
            </div>
            <div style={{ flex: 1, overflowY: "auto", padding: 12 }}>
              {findings.length === 0 ? (
                <div style={{ textAlign: "center", padding: 32 }}>
                  <div style={{ fontSize: 36, marginBottom: 12, filter: "drop-shadow(0 0 15px #06B6D4)" }}>✓</div>
                  <HoloText size={13}>Contract is Arc-compatible</HoloText>
                </div>
              ) : findings.map(f => {
                const sc = SEV[f.rule.severity], isActive = selected?.ruleId === f.ruleId && selected?.line === f.line;
                return (
                  <Glass key={`${f.ruleId}-${f.line}`} onClick={() => selectIssue(f)} glow={isActive} glowColor={sc.glow} style={{ marginBottom: 8, padding: "12px 14px", cursor: "pointer", borderLeft: `3px solid ${sc.color}`, borderRadius: "4px 10px 10px 4px", background: isActive ? sc.bg : "rgba(255,255,255,0.02)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ fontSize: 9, color: sc.color, fontWeight: 800, letterSpacing: "1.5px", textShadow: isActive ? `0 0 10px ${sc.glow}` : "none" }}>{sc.icon} {sc.label}</span>
                      <span style={{ fontSize: 9, color: "rgba(255,255,255,0.2)" }}>L{f.line}</span>
                    </div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: "#F1F5F9", marginBottom: 4, lineHeight: 1.3 }}>{f.rule.title}</div>
                    <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)" }}>{f.lineContent.slice(0, 44)}{f.lineContent.length > 44 ? "…" : ""}</div>
                  </Glass>
                );
              })}
            </div>
          </>}
        </div>

        {/* DETAIL */}
        <div style={{ width: selected ? 380 : 0, flexShrink: 0, overflow: "hidden", transition: "width 0.4s cubic-bezier(0.16,1,0.3,1)", display: "flex", flexDirection: "column" }}>
          {selected && (() => {
            const sc = SEV[selected.rule.severity], ai = selKey ? aiText[selKey] : null;
            return <>
              <div style={{ padding: "8px 16px", borderBottom: "1px solid rgba(255,255,255,0.04)", fontSize: 9, color: "rgba(255,255,255,0.2)", letterSpacing: "2px", display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(255,255,255,0.01)" }}>
                <span>ISSUE DETAIL</span>
                <button onClick={() => setSelected(null)} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.2)", cursor: "pointer", fontSize: 16, padding: 0 }}>✕</button>
              </div>
              <div style={{ flex: 1, overflowY: "auto", padding: "20px 16px" }}>
                <div style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "5px 12px", borderRadius: 20, background: sc.bg, border: `1px solid ${sc.border}`, marginBottom: 16, boxShadow: `0 0 16px ${sc.glow}`, backdropFilter: "blur(10px)" }}>
                  <span style={{ color: sc.color, fontSize: 11, fontWeight: 900 }}>{sc.icon}</span>
                  <span style={{ color: sc.color, fontSize: 9, letterSpacing: "2px", fontWeight: 800 }}>{sc.label}</span>
                  <span style={{ color: "rgba(255,255,255,0.25)", fontSize: 9 }}>LINE {selected.line}</span>
                </div>
                <div style={{ fontSize: 16, fontWeight: 900, color: "#fff", marginBottom: 6, fontFamily: "'Georgia',serif", lineHeight: 1.3, textShadow: "0 0 30px rgba(255,255,255,0.2)" }}>{selected.rule.title}</div>
                <div style={{ fontSize: 11, color: sc.color, marginBottom: 20, textShadow: `0 0 10px ${sc.glow}` }}>{selected.rule.short}</div>
                <Glass style={{ padding: "12px 14px", marginBottom: 14, border: `1px solid ${sc.border}` }}>
                  <div style={{ fontSize: 8, letterSpacing: "2px", color: "rgba(255,255,255,0.2)", marginBottom: 8 }}>FLAGGED CODE</div>
                  <code style={{ fontSize: 11, color: sc.color, whiteSpace: "pre-wrap", wordBreak: "break-all", textShadow: `0 0 8px ${sc.glow}` }}>{selected.lineContent}</code>
                </Glass>
                <Glass style={{ padding: "14px", marginBottom: 14, background: "rgba(124,58,237,0.04)", border: "1px solid rgba(124,58,237,0.15)" }}>
                  <div style={{ fontSize: 8, letterSpacing: "2px", marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}>
                    <HoloText size={8}>⬡ AI ANALYSIS</HoloText>
                    {aiLoading && <span style={{ color: "rgba(255,255,255,0.3)" }}>— LOADING…</span>}
                  </div>
                  {aiLoading
                    ? <div style={{ display: "flex", gap: 6 }}>{[0,1,2].map(i => <div key={i} style={{ width: 6, height: 6, borderRadius: "50%", background: "linear-gradient(135deg,#8B5CF6,#06B6D4)", animation: `pulse 0.8s ${i*0.2}s infinite`, boxShadow: "0 0 8px rgba(124,58,237,0.6)" }} />)}</div>
                    : <p style={{ fontSize: 12, color: "rgba(226,232,240,0.6)", lineHeight: 1.8, margin: 0, fontFamily: "'Georgia',serif" }}>{ai || selected.rule.description}</p>}
                </Glass>
                <Glass style={{ padding: "14px", marginBottom: 16 }}>
                  <div style={{ fontSize: 8, letterSpacing: "2px", color: "rgba(255,255,255,0.2)", marginBottom: 8 }}>RECOMMENDED FIX</div>
                  <p style={{ fontSize: 12, color: "rgba(226,232,240,0.55)", margin: 0, lineHeight: 1.75 }}>{selected.rule.fix}</p>
                </Glass>
                <a href={selected.rule.docs} target="_blank" rel="noreferrer" style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10, color: "rgba(255,255,255,0.2)", textDecoration: "none", letterSpacing: "1px" }}>↗ Arc Docs Reference</a>
              </div>
            </>;
          })()}
        </div>
      </div>

      {/* FOOTER */}
      <div style={{ borderTop: "1px solid rgba(255,255,255,0.04)", padding: "8px 20px", display: "flex", gap: 6, flexWrap: "wrap", background: "rgba(1,0,10,0.8)", flexShrink: 0, position: "relative", zIndex: 1, backdropFilter: "blur(10px)" }}>
        {RULES.map(r => (<span key={r.id} style={{ fontSize: 9, padding: "3px 10px", borderRadius: 20, color: SEV[r.severity].color, border: `1px solid ${SEV[r.severity].border}`, background: SEV[r.severity].bg, backdropFilter: "blur(10px)" }}>{r.short}</span>))}
      </div>

      <style>{`
        @keyframes holoShift{0%{background-position:0% 50%}100%{background-position:300% 50%}}
        @keyframes sweep{0%{transform:translateX(-100%)}100%{transform:translateX(200%)}}
        @keyframes pulse{0%,100%{opacity:0.2;transform:scale(0.8)}50%{opacity:1;transform:scale(1.3)}}
        @keyframes breathe{0%,100%{transform:scale(1);opacity:0.8}50%{transform:scale(1.1);opacity:1}}
        textarea::placeholder{color:rgba(255,255,255,0.08);}
        ::-webkit-scrollbar{width:3px;}
        ::-webkit-scrollbar-thumb{background:rgba(124,58,237,0.3);border-radius:2px;}
        ::-webkit-scrollbar-track{background:transparent;}
        *{box-sizing:border-box;}
      `}</style>
    </div>
  );
}
