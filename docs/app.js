(() => {
  const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 85;

  const textArea = document.getElementById("email-text");
  const fileInput = document.getElementById("email-file");
  const fileNameLabel = document.getElementById("file-name");
  const analyzeBtn = document.getElementById("analyze-btn");
  const errorMsg = document.getElementById("error-msg");
  const emptyState = document.getElementById("empty-state");
  const resultContent = document.getElementById("result-content");

  const gaugeFill = document.getElementById("gauge-fill");
  const gaugeScore = document.getElementById("gauge-score");
  const gaugeVerdict = document.getElementById("gauge-verdict");

  const VERDICT_COLORS = {
    safe: "var(--safe)",
    low: "var(--low)",
    medium: "var(--medium)",
    high: "var(--high)",
  };

  const MAX_TEXT_LEN = 100000;
  let selectedFile = null;

  fileInput.addEventListener("change", () => {
    selectedFile = fileInput.files[0] || null;
    fileNameLabel.textContent = selectedFile ? selectedFile.name : "";
  });

  analyzeBtn.addEventListener("click", async () => {
    hideError();
    const typed = textArea.value.trim();

    if (!selectedFile && !typed) {
      showError("Вставьте текст письма или прикрепите файл.");
      return;
    }

    setLoading(true);
    try {
      let text = typed;
      if (selectedFile) {
        text = (await readFile(selectedFile)).trim();
      }
      if (!text) {
        showError("Пустой текст — нечего анализировать.");
        return;
      }
      // Analysis runs entirely in the browser via analyzer.js.
      const data = PhishingAnalyzer.analyzeEmail(text.slice(0, MAX_TEXT_LEN));
      renderResult(data);
    } catch (err) {
      showError("Не удалось проанализировать письмо.");
    } finally {
      setLoading(false);
    }
  });

  function readFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }

  function setLoading(isLoading) {
    analyzeBtn.disabled = isLoading;
    analyzeBtn.textContent = isLoading ? "Проверяем..." : "Проверить письмо";
  }

  function showError(message) {
    errorMsg.textContent = message;
    errorMsg.hidden = false;
  }

  function hideError() {
    errorMsg.hidden = true;
  }

  function renderResult(result) {
    emptyState.hidden = true;
    resultContent.hidden = false;

    const offset = GAUGE_CIRCUMFERENCE * (1 - result.score / 100);
    gaugeFill.style.strokeDashoffset = String(offset);
    gaugeFill.style.stroke = VERDICT_COLORS[result.verdict] || "var(--accent)";
    gaugeScore.textContent = String(result.score);
    gaugeVerdict.textContent = `${result.verdict_emoji} ${result.verdict_label}`;

    const counts = { high: 0, medium: 0, low: 0 };
    for (const flag of result.flags) {
      if (counts[flag.severity] !== undefined) counts[flag.severity] += 1;
    }
    const maxCount = Math.max(1, counts.high, counts.medium, counts.low);
    for (const severity of ["high", "medium", "low"]) {
      document.getElementById(`bar-${severity}`).style.width =
        `${(counts[severity] / maxCount) * 100}%`;
      document.getElementById(`count-${severity}`).textContent = String(counts[severity]);
    }

    const findingsList = document.getElementById("findings-list");
    findingsList.innerHTML = "";
    if (result.flags.length === 0) {
      const li = document.createElement("li");
      li.className = "findings-empty";
      li.textContent = "Подозрительных признаков не найдено.";
      findingsList.appendChild(li);
    } else {
      for (const flag of result.flags) {
        const li = document.createElement("li");
        li.className = flag.severity;
        const dot = document.createElement("span");
        dot.className = `dot ${flag.severity}`;
        const text = document.createElement("span");
        text.textContent = flag.message;
        li.appendChild(dot);
        li.appendChild(text);
        findingsList.appendChild(li);
      }
    }

    const linksList = document.getElementById("links-list");
    linksList.innerHTML = "";
    document.getElementById("links-total").textContent =
      result.total_links > 0 ? `(показано ${Math.min(10, result.total_links)} из ${result.total_links})` : "";
    if (result.links.length === 0) {
      const li = document.createElement("li");
      li.textContent = "Ссылок не найдено.";
      linksList.appendChild(li);
    } else {
      for (const link of result.links.slice(0, 10)) {
        const li = document.createElement("li");
        li.className = link.flags.length > 0 ? "flagged" : "";
        li.textContent = link.url;
        linksList.appendChild(li);
      }
    }
  }
})();
