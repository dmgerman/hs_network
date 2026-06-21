--- === hs_network ===
---
--- Track network consumption per SSID/interface from the moment of connect.
--- Shows session and cumulative byte counts in the menubar, writes per-SSID
--- cumulative totals to ~/.hammerspoon/logs/network.json, and appends
--- connect/disconnect/alert events to ~/.hammerspoon/logs/network.log (TSV).
---
--- Configuration is programmatic. From your init.lua:
---
---     hs.loadSpoon("hs_network")
---     spoon.hs_network:start()
---     spoon.hs_network:setThresholds("HomeWiFi", {
---       absolute = { 1024^3, 5 * 1024^3 },  -- 1 GiB, 5 GiB
---       delta    = 500 * 1024^2,            -- every 500 MiB
---     })
---     spoon.hs_network:blacklist("WorkVPN")
---
--- Three independent toggles (all persisted to network.json):
---  * :pauseAlerts()   / :resumeAlerts()   — silence all alerts globally.
---  * :pauseTracking() / :resumeTracking() — freeze counters; on resume the
---    interface counter is re-snapshotted so paused bytes aren't backfilled.
---  * :blacklist(ssid) / :unblacklist(ssid) — silence one SSID's alerts.
---
--- Notes:
---  * SSID readout requires Location Services authorization for Hammerspoon.
---    Without it, networks are identified as `iface:en1` instead of by SSID.
---  * Byte counts come from the kernel via `netstat -ibn`. They reflect
---    physical-layer traffic on the interface, so VPN-tunneled bytes are
---    included.

local obj = {}
obj.__index = obj

obj.name = "hs_network"
obj.version = "0.2"
obj.author = "Daniel German <dmg@turingmachine.org>"
obj.license = "MIT - https://opensource.org/licenses/MIT"

-- ─── Constants ─────────────────────────────────────────────────────────────

local POLL_SECONDS   = 15
local ALERT_DURATION = 5
local DEFAULT_DELTA  = 10 * 1024^2   -- 10 MiB, applied to networks not yet
                                     -- configured. User-set values (including
                                     -- "None"/nil) persist and override.
local HOME           = os.getenv("HOME")
local LOGS_DIR       = HOME .. "/.hammerspoon/logs"
local STATE_PATH     = LOGS_DIR .. "/network.json"
local LOG_PATH       = LOGS_DIR .. "/network.log"

local log = hs.logger.new("hs_network", "info")

-- ─── Module-local state (forward-declared so closures bind correctly) ─────

local state       = nil   -- loaded JSON: ssids, alerts_paused, tracking_paused
local current     = nil   -- active session: ssid, iface, prev, session, ...
local menubar     = nil
local timer       = nil
local wifiW       = nil
local thresholds  = {}    -- ssid -> { absolute = { sorted asc }, delta = bytes }

-- ─── Formatting helpers ───────────────────────────────────────────────────

local function formatBytes(n)
  n = n or 0
  if n < 1024            then return string.format("%dB",   n) end
  if n < 1024^2          then return string.format("%.1fKB", n / 1024) end
  if n < 1024^3          then return string.format("%.1fMB", n / 1024^2) end
  return string.format("%.2fGB", n / 1024^3)
end

local function nowIso()
  return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

local function totalBytes(s)
  return (s["in"] or 0) + (s["out"] or 0)
end

-- ─── File I/O ──────────────────────────────────────────────────────────────

local function readFile(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local body = f:read("*a")
  f:close()
  return body
end

local function writeFile(path, body)
  local f = io.open(path, "w")
  if not f then log.e("cannot write " .. path); return end
  f:write(body)
  f:close()
end

local function appendFile(path, body)
  local f = io.open(path, "a")
  if not f then log.e("cannot append " .. path); return end
  f:write(body)
  f:close()
end

local function ensureLogsDir()
  hs.execute("mkdir -p " .. LOGS_DIR)
end

-- ─── State persistence ────────────────────────────────────────────────────

local function defaultState()
  return { ssids = {}, alerts_paused = false, tracking_paused = false }
end

local function loadState()
  local body = readFile(STATE_PATH)
  if not body or body == "" then return defaultState() end
  local ok, data = pcall(hs.json.decode, body)
  if not ok or type(data) ~= "table" or type(data.ssids) ~= "table" then
    log.w("state file unreadable, starting fresh")
    return defaultState()
  end
  data.alerts_paused   = data.alerts_paused   == true
  data.tracking_paused = data.tracking_paused == true
  return data
end

local function saveState()
  if not state then return end
  local body = hs.json.encode(state, true)
  if body then writeFile(STATE_PATH, body) end
end

local function logEvent(network, event, total, delta)
  local line = string.format("%s\t%s\t%s\t%d\t%d\n",
    nowIso(), network or "-", event, total or 0, delta or 0)
  appendFile(LOG_PATH, line)
end

local function ensureLoaded()
  if state then return end
  ensureLogsDir()
  state = loadState()
end

local function ensureSsidEntry(ssid)
  state.ssids[ssid] = state.ssids[ssid] or { ["in"] = 0, ["out"] = 0 }
  return state.ssids[ssid]
end

local function ssidAlertsDisabled(ssid)
  local entry = state.ssids[ssid]
  return entry ~= nil and entry.alerts_disabled == true
end

-- ─── Interface + counter detection ─────────────────────────────────────────

local function wifiInterface()
  local ifaces = hs.wifi.interfaces() or {}
  for _, iface in ipairs(ifaces) do
    local details = hs.network.interfaceDetails(iface)
    if details and details.IPv4 then return iface end
  end
  return nil
end

local function defaultRouteInterface()
  local out = hs.execute("route -n get default 2>/dev/null | awk '/interface:/{print $2}'")
  if not out then return nil end
  local iface = out:gsub("%s+", "")
  if iface == "" then return nil end
  if iface:match("^utun") or iface:match("^ppp") or iface:match("^ipsec") then
    return nil
  end
  return iface
end

local function detectActiveInterface()
  return wifiInterface() or defaultRouteInterface()
end

local function networkIdFor(iface)
  if not iface then return nil end
  local ssid = hs.wifi.currentNetwork(iface)
  if ssid and ssid ~= "" then return ssid end
  return "iface:" .. iface
end

local function readCounter(iface)
  if not iface then return nil end
  local cmd = string.format(
    "netstat -ibn 2>/dev/null | awk '$1==\"%s\" && $3 ~ /Link/{print $7, $10; exit}'",
    iface)
  local out = hs.execute(cmd)
  if not out or out == "" then return nil end
  local ib, ob = out:match("(%d+)%s+(%d+)")
  if not ib then return nil end
  return { ["in"] = tonumber(ib), ["out"] = tonumber(ob) }
end

-- ─── Alerts ────────────────────────────────────────────────────────────────

local function fireAlert(message)
  hs.alert.show(message, ALERT_DURATION)
  log.i(message)
end

local function isWifiInterface(iface)
  if not iface then return false end
  for _, w in ipairs(hs.wifi.interfaces() or {}) do
    if w == iface then return true end
  end
  return false
end

local function maybeDisableWifi(ssid, sessionTotal)
  local entry = state.ssids[ssid]
  if not entry or not entry.disable_wifi_on_cap then return end
  if not current or current.wifiKillFired then return end
  if not isWifiInterface(current.iface) then return end
  current.wifiKillFired = true
  fireAlert(string.format("⚠ %s: cap reached — disabling Wi-Fi", ssid))
  logEvent(ssid, "wifi_disabled", sessionTotal, 0)
  hs.wifi.setPower(false, current.iface)
end

local function checkAbsoluteThresholds(ssid, sessionTotal, cfg)
  for _, threshold in ipairs(cfg.absolute or {}) do
    if sessionTotal >= threshold and not current.absoluteFired[threshold] then
      current.absoluteFired[threshold] = true
      fireAlert(string.format("⚠ %s: %s reached", ssid, formatBytes(threshold)))
      logEvent(ssid, "alert_absolute", sessionTotal, threshold)
      maybeDisableWifi(ssid, sessionTotal)
    end
  end
end

local function checkDeltaThreshold(ssid, sessionTotal, cfg)
  if not cfg.delta or cfg.delta <= 0 then return end
  local consumedSinceMark = sessionTotal - current.deltaMark
  if consumedSinceMark < cfg.delta then return end
  local steps = math.floor(consumedSinceMark / cfg.delta)
  current.deltaMark = current.deltaMark + steps * cfg.delta
  fireAlert(string.format("⚠ %s: +%s consumed (total %s)",
    ssid, formatBytes(steps * cfg.delta), formatBytes(sessionTotal)))
  logEvent(ssid, "alert_delta", sessionTotal, steps * cfg.delta)
end

local function maybeAlert(ssid, sessionTotal)
  if state.alerts_paused then return end
  if ssidAlertsDisabled(ssid) then return end
  local cfg = thresholds[ssid]
  if not cfg then return end
  checkAbsoluteThresholds(ssid, sessionTotal, cfg)
  checkDeltaThreshold(ssid, sessionTotal, cfg)
end

-- ─── Session lifecycle ─────────────────────────────────────────────────────

local function applyDefaultsIfNeeded(ssid)
  local entry = ensureSsidEntry(ssid)
  if entry.thresholds == nil then
    entry.thresholds = { delta = DEFAULT_DELTA, absolute = {} }
    thresholds[ssid] = entry.thresholds
  end
end

local function startSession(iface, ssid, counter)
  current = {
    iface         = iface,
    ssid          = ssid,
    prev          = counter,
    session       = { ["in"] = 0, ["out"] = 0 },
    absoluteFired = {},
    deltaMark     = 0,
  }
  applyDefaultsIfNeeded(ssid)
  local cum = ensureSsidEntry(ssid)
  cum.last_seen = nowIso()
  saveState()
  logEvent(ssid, "connect", 0, 0)
  log.i("session start: " .. ssid .. " (" .. iface .. ")")
end

local function endSession()
  if not current then return end
  logEvent(current.ssid, "disconnect", totalBytes(current.session),
           totalBytes(current.session))
  log.i("session end: " .. current.ssid)
  current = nil
end

local function applyDelta(di, dout)
  current.session["in"]  = current.session["in"]  + di
  current.session["out"] = current.session["out"] + dout
  local cum = ensureSsidEntry(current.ssid)
  cum["in"]    = cum["in"]    + di
  cum["out"]   = cum["out"]   + dout
  cum.last_seen = nowIso()
end

-- ─── Menubar rendering ────────────────────────────────────────────────────

local function titleIndicator()
  if not state then return "" end
  if state.tracking_paused then return "⏸ " end
  if state.alerts_paused   then return "🔕 " end
  return ""
end

local function updateMenubarTitle()
  if not menubar then return end
  if not current then menubar:setTitle(titleIndicator() .. "net: --"); return end
  local s = current.session
  menubar:setTitle(string.format("%s↓%s ↑%s",
    titleIndicator(), formatBytes(s["in"]), formatBytes(s["out"])))
end

local function describeThresholds(ssid)
  local cfg = thresholds[ssid]
  local parts = {}
  if cfg and cfg.delta and cfg.delta > 0 then
    table.insert(parts, "every " .. formatBytes(cfg.delta))
  end
  if cfg and cfg.absolute and #cfg.absolute > 0 then
    local marks = {}
    for _, t in ipairs(cfg.absolute) do table.insert(marks, formatBytes(t)) end
    table.insert(parts, "at " .. table.concat(marks, ", "))
  end
  local body = (#parts > 0) and table.concat(parts, " · ") or "none configured"
  local suffix = ""
  if state.alerts_paused        then suffix = " (paused)"
  elseif ssidAlertsDisabled(ssid) then suffix = " (muted)"
  end
  return "Alerts: " .. body .. suffix
end

local function addSessionItems(items)
  table.insert(items, { title = "Network: " .. current.ssid, disabled = true })
  table.insert(items, { title = string.format("Session: ↓%s ↑%s",
    formatBytes(current.session["in"]), formatBytes(current.session["out"])),
    disabled = true })
  local cum = ensureSsidEntry(current.ssid)
  table.insert(items, { title = string.format("Cumulative: ↓%s ↑%s",
    formatBytes(cum["in"]), formatBytes(cum["out"])), disabled = true })
  table.insert(items, { title = describeThresholds(current.ssid),
    disabled = true })
end

local DELTA_PRESETS = {
  { label = "None",     value = nil },
  { label = "10 MiB",   value = 10  * 1024^2 },
  { label = "100 MiB",  value = 100 * 1024^2 },
  { label = "500 MiB",  value = 500 * 1024^2 },
  { label = "1 GiB",    value = 1024^3 },
}

local CAP_PRESETS = {
  { label = "None",     value = nil },
  { label = "100 MiB",  value = 100 * 1024^2 },
  { label = "500 MiB",  value = 500 * 1024^2 },
  { label = "1 GiB",    value = 1024^3 },
  { label = "5 GiB",    value = 5 * 1024^3 },
}

local function setDeltaFromMenu(ssid, value)
  local cur = thresholds[ssid] or {}
  obj:setThresholds(ssid, { delta = value, absolute = cur.absolute })
end

local function setAbsoluteFromMenu(ssid, value)
  local cur  = thresholds[ssid] or {}
  local list = value and { value } or {}
  obj:setThresholds(ssid, { delta = cur.delta, absolute = list })
end

local function singleAbsolute(cur)
  if not cur.absolute or #cur.absolute ~= 1 then return nil end
  return cur.absolute[1]
end

local function addDeltaSubmenu(items)
  local ssid = current.ssid
  local cur  = thresholds[ssid] or {}
  local sub  = {}
  for _, p in ipairs(DELTA_PRESETS) do
    table.insert(sub, {
      title   = p.label,
      checked = cur.delta == p.value,
      fn      = function() setDeltaFromMenu(ssid, p.value) end,
    })
  end
  table.insert(items, { title = "Set delta", menu = sub })
end

local function addCapSubmenu(items)
  local ssid = current.ssid
  local cur  = thresholds[ssid] or {}
  local sub  = {}
  local currentCap = singleAbsolute(cur)
  for _, p in ipairs(CAP_PRESETS) do
    local checked = (p.value == nil and (not cur.absolute or #cur.absolute == 0))
                 or (p.value ~= nil and currentCap == p.value)
    table.insert(sub, {
      title   = p.label,
      checked = checked,
      fn      = function() setAbsoluteFromMenu(ssid, p.value) end,
    })
  end
  table.insert(items, { title = "Set session cap", menu = sub })
end

local function addWifiKillToggle(items)
  local ssid  = current.ssid
  local entry = ensureSsidEntry(ssid)
  table.insert(items, {
    title   = "Disable Wi-Fi when cap reached",
    checked = entry.disable_wifi_on_cap == true,
    fn = function()
      entry.disable_wifi_on_cap = not entry.disable_wifi_on_cap or nil
      saveState()
    end,
  })
end

local function addPerNetworkToggle(items)
  local ssid = current.ssid
  if ssidAlertsDisabled(ssid) then
    table.insert(items, { title = "Enable alerts for " .. ssid,
      fn = function() obj:unblacklist(ssid) end })
  else
    table.insert(items, { title = "Disable alerts for " .. ssid,
      fn = function() obj:blacklist(ssid) end })
  end
end

local function addGlobalToggles(items)
  if state.alerts_paused then
    table.insert(items, { title = "Resume all alerts",
      fn = function() obj:resumeAlerts() end })
  else
    table.insert(items, { title = "Pause all alerts",
      fn = function() obj:pauseAlerts() end })
  end
  if state.tracking_paused then
    table.insert(items, { title = "Resume tracking",
      fn = function() obj:resumeTracking() end })
  else
    table.insert(items, { title = "Pause tracking",
      fn = function() obj:pauseTracking() end })
  end
end

local function addResetItem(items)
  table.insert(items, { title = "Reset session", fn = function()
    if not current then return end
    current.session       = { ["in"] = 0, ["out"] = 0 }
    current.absoluteFired = {}
    current.deltaMark     = 0
    updateMenubarTitle()
  end })
end

local function addCumulativeList(items)
  table.insert(items, { title = "-" })
  table.insert(items, { title = "All networks (cumulative)", disabled = true })
  local sorted = {}
  for ssid, _ in pairs(state.ssids) do table.insert(sorted, ssid) end
  table.sort(sorted)
  for _, ssid in ipairs(sorted) do
    local c = state.ssids[ssid]
    local muted = c.alerts_disabled and "  🔕" or "    "
    table.insert(items, { title = string.format("%s %s: ↓%s ↑%s",
      muted, ssid, formatBytes(c["in"]), formatBytes(c["out"])),
      disabled = true })
  end
end

local function buildMenu()
  local items = {}
  if current then
    addSessionItems(items)
    table.insert(items, { title = "-" })
    addDeltaSubmenu(items)
    addCapSubmenu(items)
    addWifiKillToggle(items)
    addPerNetworkToggle(items)
    addResetItem(items)
  else
    table.insert(items, { title = "Not connected", disabled = true })
  end
  table.insert(items, { title = "-" })
  addGlobalToggles(items)
  addCumulativeList(items)
  return items
end

-- ─── Poll loop ─────────────────────────────────────────────────────────────

local function pollWhenIdle()
  local iface = detectActiveInterface()
  if not iface then return end
  local ssid    = networkIdFor(iface)
  local counter = readCounter(iface)
  if not ssid or not counter then return end
  startSession(iface, ssid, counter)
end

-- Consume bytes accumulated since the last counter snapshot without firing
-- alerts. Used by setThresholds to bring the session up to "now" before
-- arming new thresholds.
local function consumeSilently()
  if not current then return end
  local counter = readCounter(current.iface)
  if not counter then return end
  local di   = math.max(0, counter["in"]  - current.prev["in"])
  local dout = math.max(0, counter["out"] - current.prev["out"])
  current.prev = counter
  if di == 0 and dout == 0 then return end
  applyDelta(di, dout)
  saveState()
end

local function pollWhenActive()
  consumeSilently()
  maybeAlert(current.ssid, totalBytes(current.session))
end

local function poll()
  if state.tracking_paused then
    updateMenubarTitle()
    return
  end
  if current then pollWhenActive() else pollWhenIdle() end
  updateMenubarTitle()
end

local function onWifiChange()
  if state.tracking_paused then return end
  local iface = detectActiveInterface()
  local ssid  = iface and networkIdFor(iface) or nil
  if current and (current.iface ~= iface or current.ssid ~= ssid) then
    endSession()
  end
  poll()
end

-- ─── Public API: configuration ────────────────────────────────────────────

--- hs_network:setThresholds(ssid, opts)
--- Method
--- Configure alert thresholds for an SSID.
---
--- Parameters:
---  * ssid - string network identifier (SSID or "iface:NAME")
---  * opts - table with optional fields:
---     * absolute - list of byte counts; one alert per threshold per session
---     * delta    - alert every N bytes consumed in the current session
local function persistThresholds(ssid)
  local entry = ensureSsidEntry(ssid)
  entry.thresholds = thresholds[ssid]
  saveState()
end

local function applyThresholdsToCurrent(ssid)
  if not current or current.ssid ~= ssid then return end
  local cfg = thresholds[ssid] or {}
  local sessionTotal = totalBytes(current.session)
  current.deltaMark = sessionTotal
  current.absoluteFired = {}
  for _, threshold in ipairs(cfg.absolute or {}) do
    if sessionTotal >= threshold then
      current.absoluteFired[threshold] = true
    end
  end
end

function obj:setThresholds(ssid, opts)
  ensureLoaded()
  opts = opts or {}
  local abs = {}
  for _, v in ipairs(opts.absolute or {}) do table.insert(abs, v) end
  table.sort(abs)
  if current and current.ssid == ssid then consumeSilently() end
  thresholds[ssid] = { absolute = abs, delta = opts.delta }
  applyThresholdsToCurrent(ssid)
  persistThresholds(ssid)
  return self
end

--- hs_network:blacklist(ssid)
--- Method
--- Suppress alerts for the given network. Consumption is still counted.
--- Persists to ~/.hammerspoon/logs/network.json.
function obj:blacklist(ssid)
  ensureLoaded()
  ensureSsidEntry(ssid).alerts_disabled = true
  saveState()
  return self
end

--- hs_network:unblacklist(ssid)
--- Method
--- Re-enable alerts for the given network. Persists to disk.
function obj:unblacklist(ssid)
  ensureLoaded()
  ensureSsidEntry(ssid).alerts_disabled = nil
  saveState()
  return self
end

-- ─── Public API: global pause toggles ─────────────────────────────────────

--- hs_network:pauseAlerts()
--- Method
--- Silence all alerts. Counting and the menubar continue. Persists to disk.
function obj:pauseAlerts()
  ensureLoaded()
  state.alerts_paused = true
  saveState()
  updateMenubarTitle()
  log.i("alerts paused")
  return self
end

--- hs_network:resumeAlerts()
--- Method
--- Re-enable alerts globally. Per-SSID blacklist still applies.
function obj:resumeAlerts()
  ensureLoaded()
  state.alerts_paused = false
  saveState()
  updateMenubarTitle()
  log.i("alerts resumed")
  return self
end

--- hs_network:toggleAlerts()
--- Method
--- Flip the global-alerts-paused flag.
function obj:toggleAlerts()
  ensureLoaded()
  if state.alerts_paused then return self:resumeAlerts() end
  return self:pauseAlerts()
end

--- hs_network:isAlertsPaused() -> boolean
function obj:isAlertsPaused()
  ensureLoaded()
  return state.alerts_paused == true
end

--- hs_network:pauseTracking()
--- Method
--- Freeze counters. Menubar stays visible with a ⏸ indicator showing the
--- last values. No alerts fire. Persists to disk.
function obj:pauseTracking()
  ensureLoaded()
  state.tracking_paused = true
  saveState()
  updateMenubarTitle()
  log.i("tracking paused")
  return self
end

--- hs_network:resumeTracking()
--- Method
--- Resume counting. The current interface counter is re-snapshotted so
--- bytes that flowed during the pause are not retroactively added.
function obj:resumeTracking()
  ensureLoaded()
  state.tracking_paused = false
  saveState()
  if current then
    local counter = readCounter(current.iface)
    if counter then current.prev = counter end
  end
  updateMenubarTitle()
  log.i("tracking resumed")
  return self
end

--- hs_network:toggleTracking()
--- Method
--- Flip the tracking-paused flag.
function obj:toggleTracking()
  ensureLoaded()
  if state.tracking_paused then return self:resumeTracking() end
  return self:pauseTracking()
end

--- hs_network:isTrackingPaused() -> boolean
function obj:isTrackingPaused()
  ensureLoaded()
  return state.tracking_paused == true
end

-- ─── Public API: lifecycle ────────────────────────────────────────────────

--- hs_network:start()
--- Method
--- Begin polling, watching Wi-Fi changes, and rendering the menubar item.
--- Honors persisted alerts_paused / tracking_paused flags.
local function hydrateThresholds()
  for ssid, entry in pairs(state.ssids) do
    if type(entry.thresholds) == "table" then
      thresholds[ssid] = entry.thresholds
    end
  end
end

function obj:start()
  ensureLoaded()
  hydrateThresholds()
  if not menubar then menubar = hs.menubar.new() end
  menubar:setMenu(buildMenu)
  updateMenubarTitle()
  if not timer then timer = hs.timer.doEvery(POLL_SECONDS, poll) end
  if not wifiW then
    wifiW = hs.wifi.watcher.new(onWifiChange)
    wifiW:start()
  end
  poll()
  log.i("started")
  return self
end

--- hs_network:stop()
--- Method
--- Stop watchers and remove the menubar item. State on disk is preserved.
function obj:stop()
  if timer   then timer:stop();   timer   = nil end
  if wifiW   then wifiW:stop();   wifiW   = nil end
  if menubar then menubar:delete(); menubar = nil end
  endSession()
  log.i("stopped")
  return self
end

--- hs_network:resetSession()
--- Method
--- Zero out the current session counters and alert state for the active SSID.
function obj:resetSession()
  if not current then return self end
  current.session       = { ["in"] = 0, ["out"] = 0 }
  current.absoluteFired = {}
  current.deltaMark     = 0
  updateMenubarTitle()
  return self
end

--- hs_network:resetCumulative(ssid)
--- Method
--- Zero out the per-SSID cumulative total. Without an SSID, resets all.
function obj:resetCumulative(ssid)
  ensureLoaded()
  if ssid then
    local entry = state.ssids[ssid] or {}
    state.ssids[ssid] = {
      ["in"] = 0, ["out"] = 0,
      last_seen = nowIso(),
      alerts_disabled = entry.alerts_disabled,
    }
  else
    state.ssids = {}
  end
  saveState()
  return self
end

return obj
