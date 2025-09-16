"use strict";

// App State
const state = {
  home: {
    light: false,
    lock: true,
    thermostat: 22,
    energyHistory: new Array(60).fill(0)
  },
  city: {
    traffic: { mode: "auto", flowHistory: new Array(60).fill(30) },
    lights: false,
    aqi: 22
  },
  factory: {
    conveyor: false,
    robot: false,
    temperature: 42,
    outputHistory: new Array(60).fill(40)
  }
};

// Utils
const $ = (q) => document.querySelector(q);
const $$ = (q) => Array.from(document.querySelectorAll(q));

function log(message, status = "info") {
  const out = $("#console-output");
  const el = document.createElement("div");
  el.className = "log";
  const classByStatus = { ok: "ok", warn: "warn", err: "err" };
  el.innerHTML = `<span class="${classByStatus[status] || ""}">${escapeHtml(message)}</span>`;
  out.appendChild(el);
  out.scrollTop = out.scrollHeight;
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"]+/g, s => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[s]));
}

// Minimal charting helper (no deps)
function drawLineChart(canvasId, values, color = "#4da3ff", yMin = 0, yMax = 100) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.strokeStyle = "rgba(255,255,255,0.1)";
  ctx.lineWidth = 1;
  // grid
  for (let i = 0; i <= 4; i++) {
    const y = (h / 4) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
  // line
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.beginPath();
  values.forEach((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - ((v - yMin) / (yMax - yMin)) * h;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function updateUIFromState() {
  // Home
  $("[data-device='home.light']").textContent = state.home.light ? "On" : "Off";
  $("[data-device='home.light']").className = `toggle ${state.home.light ? "on" : "off"}`;
  $("[data-device='home.lock']").textContent = state.home.lock ? "Locked" : "Unlocked";
  $("[data-device='home.lock']").className = `toggle ${state.home.lock ? "on" : "off"}`;
  $("#home-temp").textContent = String(state.home.thermostat);

  // City
  $("[data-device='city.traffic.auto']").textContent = state.city.traffic.mode === "auto" ? "Auto" : "Manual";
  $("[data-device='city.traffic.auto']").className = `toggle ${state.city.traffic.mode === "auto" ? "on" : "off"}`;
  $("[data-device='city.lights']").textContent = state.city.lights ? "On" : "Off";
  $("[data-device='city.lights']").className = `toggle ${state.city.lights ? "on" : "off"}`;
  $("#city-aqi").textContent = String(state.city.aqi);

  // Factory
  $("[data-device='factory.conveyor']").textContent = state.factory.conveyor ? "Running" : "Stopped";
  $("[data-device='factory.conveyor']").className = `toggle ${state.factory.conveyor ? "on" : "off"}`;
  $("[data-device='factory.robot']").textContent = state.factory.robot ? "Active" : "Idle";
  $("[data-device='factory.robot']").className = `toggle ${state.factory.robot ? "on" : "off"}`;
  $("#factory-temp").textContent = String(state.factory.temperature);

  drawLineChart("home-energy-chart", state.home.energyHistory, "#00d280", 0, 100);
  drawLineChart("city-traffic-chart", state.city.traffic.flowHistory, "#4da3ff", 0, 100);
  drawLineChart("factory-output-chart", state.factory.outputHistory, "#ffcc00", 0, 120);
}

// Simulated sensors and AI automation
function tickSensors() {
  // Home energy depends on light and thermostat
  const baseHome = 15 + (state.home.light ? 10 : 0) + Math.max(0, state.home.thermostat - 20) * 1.5;
  state.home.energyHistory.push(Math.min(100, Math.max(0, baseHome + (Math.random() * 6 - 3))));
  state.home.energyHistory.shift();

  // City traffic flow varies; if manual mode, it's static-ish
  const trafficBase = state.city.traffic.mode === "auto" ? 30 + Math.sin(Date.now() / 20000) * 20 : 40;
  state.city.traffic.flowHistory.push(Math.min(100, Math.max(0, trafficBase + (Math.random() * 10 - 5))));
  state.city.traffic.flowHistory.shift();

  // Factory output relates to conveyor and robot
  const outputBase = (state.factory.conveyor && state.factory.robot) ? 80 : (state.factory.conveyor || state.factory.robot) ? 40 : 5;
  state.factory.outputHistory.push(Math.min(120, Math.max(0, outputBase + (Math.random() * 12 - 6))));
  state.factory.outputHistory.shift();

  // AQI drifts slightly
  state.city.aqi = Math.max(8, Math.min(160, Math.round(state.city.aqi + (Math.random() * 4 - 2))));

  // Factory temp drifts
  const heat = (state.factory.conveyor || state.factory.robot) ? 0.25 : -0.05;
  state.factory.temperature = Math.max(20, Math.min(120, +(state.factory.temperature + heat + (Math.random() * 0.6 - 0.3)).toFixed(1)));
}

function runAutomationRules() {
  // Home: if energy spikes > 80, suggest actions
  const recentEnergy = state.home.energyHistory[state.home.energyHistory.length - 1];
  if (recentEnergy > 80 && state.home.light) {
    log("AI: High energy usage detected — turning off home.light", "warn");
    state.home.light = false;
  }

  // City: in auto mode, if traffic flow < 20, extend green (simulated by turning lights on)
  const recentFlow = state.city.traffic.flowHistory[state.city.traffic.flowHistory.length - 1];
  if (state.city.traffic.mode === "auto" && recentFlow < 20) {
    state.city.lights = true; // brighter streets for safety
  }

  // Factory: if temperature exceeds threshold, stop or cool
  if (state.factory.temperature > 90) {
    log("AI: Factory temperature high — pausing conveyor and robot", "err");
    state.factory.conveyor = false;
    state.factory.robot = false;
  }
}

// Command handling
function handleCommand(raw) {
  const input = raw.trim();
  if (!input) return;
  log("> " + input);
  const [cmd, ...rest] = input.split(/\s+/);
  const args = rest;
  try {
    switch (cmd.toLowerCase()) {
      case "set": {
        const target = args[0];
        const value = (args[1] || "").toLowerCase();
        if (!target) throw new Error("Usage: set <device> <value>");
        setDevice(target, value);
        log(`OK: set ${target} ${value}`, "ok");
        break;
      }
      case "mode": {
        const target = args[0];
        const value = (args[1] || "").toLowerCase();
        if (target === "city.traffic") {
          if (value !== "auto" && value !== "manual") throw new Error("Value must be auto|manual");
          state.city.traffic.mode = value;
          break;
        }
        throw new Error("Unsupported mode target");
      }
      case "thermostat": {
        const val = Number(args[0]);
        if (Number.isNaN(val) || val < 16 || val > 30) throw new Error("Thermostat range 16-30");
        state.home.thermostat = Math.round(val);
        log(`OK: thermostat ${val}`, "ok");
        break;
      }
      case "status": {
        log(JSON.stringify(state, null, 2));
        break;
      }
      case "help":
      default:
        log("Commands: set, mode, thermostat, status, help");
    }
  } catch (e) {
    log("Error: " + e.message, "err");
  }
  updateUIFromState();
}

function setDevice(target, value) {
  switch (target) {
    case "home.light":
      state.home.light = value === "on";
      return;
    case "home.lock":
      if (value !== "lock" && value !== "unlock") throw new Error("lock|unlock");
      state.home.lock = value === "lock";
      return;
    case "city.lights":
      state.city.lights = value === "on";
      return;
    case "factory.conveyor":
      if (value !== "start" && value !== "stop") throw new Error("start|stop");
      state.factory.conveyor = value === "start";
      return;
    case "factory.robot":
      if (value !== "start" && value !== "stop") throw new Error("start|stop");
      state.factory.robot = value === "start";
      return;
    default:
      throw new Error("Unknown device");
  }
}

// Wire up UI
function initUI() {
  $$(".toggle").forEach(btn => {
    btn.addEventListener("click", () => {
      const device = btn.getAttribute("data-device");
      switch (device) {
        case "home.light": setDevice(device, state.home.light ? "off" : "on"); break;
        case "home.lock": setDevice(device, state.home.lock ? "unlock" : "lock"); break;
        case "city.traffic.auto": state.city.traffic.mode = state.city.traffic.mode === "auto" ? "manual" : "auto"; break;
        case "city.lights": setDevice("city.lights", state.city.lights ? "off" : "on"); break;
        case "factory.conveyor": setDevice("factory.conveyor", state.factory.conveyor ? "stop" : "start"); break;
        case "factory.robot": setDevice("factory.robot", state.factory.robot ? "stop" : "start"); break;
      }
      updateUIFromState();
    });
  });

  $("#thermostat-slider").addEventListener("input", (e) => {
    state.home.thermostat = parseInt(e.target.value, 10);
    updateUIFromState();
  });

  $("#refresh-aqi").addEventListener("click", () => {
    state.city.aqi = 10 + Math.floor(Math.random() * 120);
    updateUIFromState();
    log("AQI refreshed");
  });

  $("#cooling-boost").addEventListener("click", () => {
    state.factory.temperature = Math.max(20, state.factory.temperature - 5);
    updateUIFromState();
    log("Cooling boost applied", "ok");
  });

  $("#console-send").addEventListener("click", () => {
    const input = $("#console-input");
    handleCommand(input.value);
    input.value = "";
    input.focus();
  });
  $("#console-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#console-send").click();
  });
}

// Main loop
function loop() {
  tickSensors();
  runAutomationRules();
  updateUIFromState();
  requestAnimationFrame(loop);
}

window.addEventListener("DOMContentLoaded", () => {
  initUI();
  updateUIFromState();
  log("Ready. Type 'help' for commands.", "ok");
  requestAnimationFrame(loop);
});



