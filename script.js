
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js"
import { getDatabase, ref, onValue } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-database.js"

const firebaseConfig = {
  apiKey: "AIzaSyByM5CbPjCo6WSeb4RU2_RA_IPQEmKdLBA",
  authDomain: "honeypot-715b9.firebaseapp.com",
  projectId: "honeypot-715b9",
  storageBucket: "honeypot-715b9.firebasestorage.app",
  messagingSenderId: "556848903405",
  appId: "1:556848903405:web:b338b330f3c02d042cc8e4",
  databaseURL: "https://honeypot-715b9-default-rtdb.firebaseio.com/",
}

const app = initializeApp(firebaseConfig)
const db = getDatabase(app)


let allLogs = []
let filteredLogs = []
let attackTypesData = {}


const tableBody = document.getElementById("log-table-body")
const searchInput = document.getElementById("searchInput")
const filterSelect = document.getElementById("filterAttackType")
const loadingOverlay = document.getElementById("loadingOverlay")


function getAttackTypeInfo(attackType) {
  const attackTypes = {
    "SQL Injection": { risk: "high", icon: "fas fa-database", color: "#ff6b6b" },
    "XSS Attack": { risk: "high", icon: "fas fa-code", color: "#ff6b6b" },
    "Command Injection": { risk: "high", icon: "fas fa-terminal", color: "#ff6b6b" },
    "Curl Request": { risk: "medium", icon: "fas fa-download", color: "#ffc107" },
    "Wget Request": { risk: "medium", icon: "fas fa-download", color: "#ffc107" },
    "Port Scan / Recon Tool": { risk: "medium", icon: "fas fa-search", color: "#ffc107" },
    "Brute Force Attempt": { risk: "high", icon: "fas fa-key", color: "#ff6b6b" },
    "Web Shell Probe": { risk: "high", icon: "fas fa-bug", color: "#ff6b6b" },
    "Basic HTTP Probe": { risk: "low", icon: "fas fa-globe", color: "#4caf50" },
    "Binary Payload / Encoded Probe": { risk: "medium", icon: "fas fa-file-code", color: "#ffc107" },
    Unknown: { risk: "low", icon: "fas fa-question", color: "#6c757d" },
    "No Payload": { risk: "low", icon: "fas fa-minus", color: "#6c757d" },
  }

  return attackTypes[attackType] || attackTypes["Unknown"]
}


function showLoading() {
  loadingOverlay.classList.add("active")
}

function hideLoading() {
  loadingOverlay.classList.remove("active")
}


function updateStats() {
  const totalAttacks = allLogs.length
  const uniqueIPs = new Set(allLogs.map((log) => log.ip)).size
  const attackTypes = new Set(allLogs.map((log) => log.attack_type || "Unknown")).size
  const lastAttack = allLogs.length > 0 ? new Date(allLogs[0].time).toLocaleString("en-US") : "--"

  document.getElementById("total-attacks").textContent = totalAttacks
  document.getElementById("unique-ips").textContent = uniqueIPs
  document.getElementById("attack-types").textContent = attackTypes
  document.getElementById("last-attack").textContent = lastAttack
}


function updateAttackTypesAnalysis() {
  attackTypesData = {}
  allLogs.forEach((log) => {
    const attackType = log.attack_type || "Unknown"
    attackTypesData[attackType] = (attackTypesData[attackType] || 0) + 1
  })

  const grid = document.getElementById("attack-types-grid")
  grid.innerHTML = ""

  Object.entries(attackTypesData)
    .sort(([, a], [, b]) => b - a)
    .forEach(([type, count]) => {
      const info = getAttackTypeInfo(type)
      const card = document.createElement("div")
      card.className = "attack-type-card"
      card.innerHTML = `
        <i class="${info.icon}" style="color: ${info.color}; font-size: 1.5rem; margin-bottom: 0.5rem;"></i>
        <h4>${type}</h4>
        <div class="attack-count">${count}</div>
      `
      grid.appendChild(card)
    })


    filterSelect.innerHTML = '<option value="">All Attack Types</option>'
  Object.keys(attackTypesData)
    .sort()
    .forEach((type) => {
      const option = document.createElement("option")
      option.value = type
      option.textContent = type
      filterSelect.appendChild(option)
    })
}


function formatPayload(payload) {
  if (!payload || payload === "<NO PAYLOAD>") return "No Data"
  if (payload.length > 100) {
    return payload.substring(0, 100) + "..."
  }
  return payload
}


function renderTable(logs = filteredLogs) {
  tableBody.innerHTML = ""

  logs.forEach((log) => {
    const attackType = log.attack_type || "Unknown"
    const info = getAttackTypeInfo(attackType)
    const row = document.createElement("tr")

    row.innerHTML = `
      <td><strong>${log.ip}</strong></td>
      <td>${log.port}</td>
      <td><div class="payload-cell">${formatPayload(log.data)}</div></td>
      <td>
        <div class="attack-type-badge risk-${info.risk}">
          <i class="${info.icon}"></i> ${attackType}
        </div>
      </td>
      <td>${new Date(log.time).toLocaleString("en-US")}</td>
      <td><span class="attack-type-badge risk-${info.risk}">${info.risk === "high" ? "High" : info.risk === "medium" ? "Medium" : "Low"}</span></td>
    `

    tableBody.appendChild(row)
  })
}


function applyFilters() {
  const searchTerm = searchInput.value.toLowerCase()
  const selectedType = filterSelect.value

  filteredLogs = allLogs.filter((log) => {
    const matchesSearch =
      !searchTerm ||
      log.ip.toLowerCase().includes(searchTerm) ||
      (log.data && log.data.toLowerCase().includes(searchTerm)) ||
      (log.attack_type && log.attack_type.toLowerCase().includes(searchTerm))

    const matchesType = !selectedType || log.attack_type === selectedType

    return matchesSearch && matchesType
  })

  renderTable()
}


function exportData() {
  const dataStr = JSON.stringify(allLogs, null, 2)
  const dataBlob = new Blob([dataStr], { type: "application/json" })
  const url = URL.createObjectURL(dataBlob)
  const link = document.createElement("a")
  link.href = url
  link.download = `honeypot-logs-${new Date().toISOString().split("T")[0]}.json`
  link.click()
  URL.revokeObjectURL(url)
}


searchInput.addEventListener("input", applyFilters)
filterSelect.addEventListener("change", applyFilters)
document.getElementById("refreshData").addEventListener("click", () => {
  showLoading()
  setTimeout(hideLoading, 1000)
})
document.getElementById("exportData").addEventListener("click", exportData)


function logout() {
  localStorage.removeItem("isLoggedIn")
  window.location.href = "admin-login.html"
}


window.logout = logout


const logRef = ref(db, "honeypot_logs")
showLoading()

onValue(logRef, (snapshot) => {
  const logs = snapshot.val()

  if (logs) {
    allLogs = Object.values(logs).reverse() 
    filteredLogs = [...allLogs]

    updateStats()
    updateAttackTypesAnalysis()
    renderTable()

    window.dispatchEvent(
      new CustomEvent("firebaseDataLoaded", {
        detail: { data: allLogs },
      }),
    )
  } else {
    console.warn("⚠️ No logs found in Firebase.")
    allLogs = []
    filteredLogs = []
  }

  hideLoading()
})


if (!localStorage.getItem("isLoggedIn")) {
  window.location.href = "admin-login.html"
}
