const form = document.querySelector("#readForm");
const readButton = document.querySelector("#readButton");
const statusEl = document.querySelector("#status");
const summaryEl = document.querySelector("#summary");
const registerRows = document.querySelector("#registerRows");
const sessionDetails = document.querySelector("#sessionDetails");

function setStatus(message, kind = "idle") {
  statusEl.textContent = message;
  statusEl.className = `status ${kind}`;
}

function formPayload() {
  return Object.fromEntries(new FormData(form).entries());
}

function renderRegisters(registers) {
  if (!registers.length) {
    registerRows.innerHTML = '<tr><td colspan="3" class="empty">未读取到寄存器</td></tr>';
    return;
  }

  registerRows.innerHTML = registers
    .map(
      (row) => `
        <tr>
          <td>${row.address}</td>
          <td>${row.value}</td>
          <td>${row.hex}</td>
        </tr>
      `,
    )
    .join("");
}

function renderDetails(result) {
  const items = [
    ["从站端点", result.endpoint],
    ["从站地址", result.slave_id],
    ["起始地址", result.start],
    ["读取数量", result.quantity],
    ["安全模式", result.master.mode],
    ["客户端 ID", result.master.client_id],
    ["服务器 ID", result.master.server_id],
    ["内容密钥 CK", result.master.ck],
    ["内容 IV", result.master.civ],
  ];

  sessionDetails.innerHTML = items
    .map(([key, value]) => `<dt>${key}</dt><dd>${value}</dd>`)
    .join("");
}

async function readRegisters() {
  readButton.disabled = true;
  setStatus("正在握手并读取寄存器...");
  summaryEl.textContent = "读取中";

  try {
    const response = await fetch("/api/read", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(formPayload()),
    });
    const body = await response.json();
    if (!response.ok || !body.ok) {
      throw new Error(body.error || `HTTP ${response.status}`);
    }

    renderRegisters(body.result.registers);
    renderDetails(body.result);
    summaryEl.textContent = `${body.result.registers.length} 个寄存器`;
    setStatus("读取完成", "ok");
  } catch (error) {
    setStatus(error.message, "error");
    summaryEl.textContent = "读取失败";
  } finally {
    readButton.disabled = false;
  }
}

readButton.addEventListener("click", readRegisters);
form.addEventListener("submit", (event) => {
  event.preventDefault();
  readRegisters();
});
