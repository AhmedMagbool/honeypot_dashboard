
const ctx = document.getElementById("attackChart").getContext("2d")
let currentView = "perDay"
let currentType = "bar"
let chart


function groupByDay(data) {
  const map = {}
  data.forEach((entry) => {
    if (!entry.time) return

    let dateObj
    if (typeof entry.time === "number") {
      dateObj = new Date(entry.time)
    } else if (typeof entry.time === "string" && entry.time.includes(":")) {
      const formatted = entry.time.replace(" ", "T")
      dateObj = new Date(formatted)
    } else {
      dateObj = new Date(entry.time)
    }

    if (isNaN(dateObj.getTime())) return

    const date = dateObj.toISOString().split("T")[0]
    map[date] = (map[date] || 0) + 1
  })

  const sortedEntries = Object.entries(map).sort(([a], [b]) => new Date(a) - new Date(b))
  const sortedMap = {}
  sortedEntries.forEach(([date, count]) => {
    sortedMap[date] = count
  })
  return sortedMap
}

function groupByIP(data) {
  const map = {}
  data.forEach((entry) => {
    map[entry.ip] = (map[entry.ip] || 0) + 1
  })
  return map
}

function groupByAttackType(data) {
  const map = {}
  data.forEach((entry) => {
    const attackType = entry.attack_type || "Unknown"
    map[attackType] = (map[attackType] || 0) + 1
  })
  return map
}

function groupByHour(data) {
  const map = {}
  data.forEach((entry) => {
    if (!entry.time) return

    let dateObj
    if (typeof entry.time === "number") {
      dateObj = new Date(entry.time)
    } else if (typeof entry.time === "string" && entry.time.includes(":")) {
      const formatted = entry.time.replace(" ", "T")
      dateObj = new Date(formatted)
    } else {
      dateObj = new Date(entry.time)
    }

    if (isNaN(dateObj.getTime())) return

    const hour = dateObj.getHours()
    const hourLabel = `${hour}:00`
    map[hourLabel] = (map[hourLabel] || 0) + 1
  })
  return map
}


function renderChart(groupedData, label) {
  const labels = Object.keys(groupedData)
  const values = Object.values(groupedData)

  if (chart) chart.destroy()


    const colorSchemes = {
    perDay: {
      background: "rgba(255, 107, 107, 0.2)",
      border: "rgba(255, 107, 107, 1)",
      point: "#ff6b6b",
    },
    perIP: {
      background: "rgba(78, 205, 196, 0.2)",
      border: "rgba(78, 205, 196, 1)",
      point: "#4ecdc4",
    },
    perType: {
      background: "rgba(69, 183, 209, 0.2)",
      border: "rgba(69, 183, 209, 1)",
      point: "#45b7d1",
    },
    perHour: {
      background: "rgba(240, 147, 251, 0.2)",
      border: "rgba(240, 147, 251, 1)",
      point: "#f093fb",
    },
  }

  const generateColors = (count) => {
    const colors = [
      "#ff6b6b",
      "#4ecdc4",
      "#45b7d1",
      "#f093fb",
      "#96ceb4",
      "#feca57",
      "#ff9ff3",
      "#54a0ff",
      "#5f27cd",
      "#00d2d3",
      "#ff9f43",
      "#10ac84",
      "#ee5253",
      "#0abde3",
      "#3742fa",
    ]
    return colors.slice(0, count)
  }

  const colors = colorSchemes[currentView] || colorSchemes.perDay

  let backgroundColor, borderColor
  if (currentType === "doughnut") {
    backgroundColor = generateColors(values.length)
    borderColor = backgroundColor.map((color) => color)
  } else {
    backgroundColor = colors.background
    borderColor = colors.border
  }

  chart = new window.Chart(ctx, {
    type: currentType,
    data: {
      labels,
      datasets: [
        {
          label,
          data: values,
          backgroundColor: backgroundColor,
          borderColor: borderColor,
          borderWidth: 3,
          fill: currentType === "line",
          tension: 0.4,
          borderRadius: currentType === "bar" ? 8 : 0,
          pointBackgroundColor: colors.point,
          pointBorderColor: "#fff",
          pointBorderWidth: 2,
          pointRadius: currentType === "line" ? 6 : 0,
          pointHoverRadius: currentType === "line" ? 8 : 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: "#fff",
            font: {
              size: 14,
              weight: "bold",
            },
          },
        },
        tooltip: {
          backgroundColor: "rgba(0, 0, 0, 0.8)",
          titleColor: "#fff",
          bodyColor: "#fff",
          borderColor: colors.border,
          borderWidth: 1,
        },
      },
      scales:
        currentType === "doughnut"
          ? {}
          : {
              x: {
                ticks: {
                  color: "#fff",
                  font: {
                    size: 12,
                  },
                },
                grid: {
                  color: "rgba(255, 255, 255, 0.1)",
                  drawBorder: false,
                },
              },
              y: {
                beginAtZero: true,
                ticks: {
                  color: "#fff",
                  font: {
                    size: 12,
                  },
                },
                grid: {
                  color: "rgba(255, 255, 255, 0.1)",
                  drawBorder: false,
                },
              },
            },
      animation: {
        duration: 1000,
        easing: "easeInOutQuart",
      },
    },
  })
}


let viewIndex = 0
const views = [
  { key: "perDay", label: "Daily Attacks", groupFn: groupByDay },
  { key: "perType", label: "Attacks by Type", groupFn: groupByAttackType },
  { key: "perIP", label: "Attempts by IP", groupFn: groupByIP },
  { key: "perHour", label: "Attacks by Hour", groupFn: groupByHour },
]


window.addEventListener("firebaseDataLoaded", (event) => {
  const entries = event.detail.data
  if (!entries || entries.length === 0) return

  currentView = views[0].key
  const grouped = views[0].groupFn(entries)
  renderChart(grouped, views[0].label)


  document.getElementById("toggleChart").addEventListener("click", () => {

    if (currentType === "bar") {
      currentType = "line"
    } else if (currentType === "line") {
      currentType = "doughnut"
    } else {
      currentType = "bar"
      viewIndex = (viewIndex + 1) % views.length
      currentView = views[viewIndex].key
    }

    const currentViewObj = views[viewIndex]
    const grouped = currentViewObj.groupFn(entries)
    renderChart(grouped, currentViewObj.label)
  })
})
