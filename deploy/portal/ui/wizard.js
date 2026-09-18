/* ============================================================
   IPv8+ 交互式诊断向导
   步骤0：探测本机 ping8 serve
   步骤1：逐项揭晓 9 项检查
   步骤2：总结与修复指引
   ============================================================ */
(function () {
  'use strict';

  var LOCAL_SERVE = 'http://127.0.0.1:9100';

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    if (s === null || s === undefined) { return ''; }
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fetchJSON(url, timeoutMs) {
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, timeoutMs);
    return fetch(url, { signal: ctrl.signal, cache: 'no-store' })
      .then(function (r) {
        clearTimeout(timer);
        if (!r.ok) { throw new Error('HTTP ' + r.status); }
        return r.json();
      })
      .catch(function (e) {
        clearTimeout(timer);
        throw e;
      });
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
    return Promise.resolve();
  }

  function makeTermBlock(cmd, comment) {
    return '<div class="term-block">' +
      '<div class="term-head"><div class="term-dots"><span></span><span></span><span></span></div>' +
      '<button class="copy-btn" data-copy="' + esc(cmd) + '">复制</button></div>' +
      '<div class="term-body"><span class="prompt">$</span> ' + esc(cmd) +
      (comment ? ' <span class="comment"># ' + esc(comment) + '</span>' : '') + '</div></div>';
  }

  // 状态映射
  var STATUS_ICON = { ok: '✓', warn: '!', fail: '✕', na: '-' };

  // ---------- 步骤 0：探测本机 serve ----------
  function step0() {
    var box = $('wizard-body');
    box.innerHTML = '<div class="serve-card">' +
      '<div class="icon">◐</div>' +
      '<h2>正在探测本机客户端…</h2>' +
      '<p>检测 ping8 serve 是否运行在 127.0.0.1:9100</p></div>';

    fetchJSON(LOCAL_SERVE + '/api/status', 2000)
      .then(function (d) { showServeRunning(d); })
      .catch(function () { showServeStopped(); });
  }

  function showServeRunning(d) {
    var visa = d.visa || {};
    var visaText = visa.exists
      ? (visa.addr || '-') + (visa.remaining_days >= 0 ? ' [' + visa.remaining_days + '天]' : '')
      : '未签发';

    $('wizard-body').innerHTML =
      '<div class="serve-card">' +
        '<div class="icon" style="background:var(--ok-soft);color:var(--ok)">●</div>' +
        '<h2>本机客户端运行中</h2>' +
        '<p>检测到 ping8 serve 正在运行，可以开始诊断。</p>' +
        '<div class="overview-grid">' +
          '<div class="overview-item"><div class="label">本机 IPv8 地址</div><div class="value">' + esc(visa.addr || '-') + '</div></div>' +
          '<div class="overview-item"><div class="label">签证状态</div><div class="value">' + esc(visaText) + '</div></div>' +
          '<div class="overview-item"><div class="label">客户端版本</div><div class="value">v' + esc(d.version || '?') + '</div></div>' +
        '</div>' +
        '<button class="btn btn-lg" id="start-diagnose-btn">开始诊断</button>' +
      '</div>';

    $('start-diagnose-btn').addEventListener('click', step1);
  }

  function showServeStopped() {
    $('wizard-body').innerHTML =
      '<div class="serve-card">' +
        '<div class="icon" style="background:var(--warn-soft);color:var(--warn)">○</div>' +
        '<h2>本机客户端未运行</h2>' +
        '<p>请先在本机启动 ping8 serve，诊断向导才能读取本机状态。</p>' +
        makeTermBlock('ping8 serve', '启动本地管理服务') +
        '<button class="btn" id="retry-probe-btn">重试检测</button>' +
      '</div>';

    $('retry-probe-btn').addEventListener('click', step0);
    bindCopyButtons();
  }

  // ---------- 步骤 1：逐项检查 ----------
  function step1() {
    var box = $('wizard-body');
    box.innerHTML =
      '<div class="alert alert-run">正在逐项检查，请稍候（约 2-5 秒）…</div>' +
      '<div class="check-list" id="check-list"></div>';

    fetchJSON(LOCAL_SERVE + '/api/diagnose', 10000)
      .then(function (d) {
        if (!d || !Array.isArray(d.checks) || d.checks.length === 0) {
          box.innerHTML = '<div class="alert alert-fail">客户端版本过旧，不支持诊断 API。请更新 ping8.exe。</div>' +
            makeTermBlock('ping8 auto', '更新客户端');
          bindCopyButtons();
          return;
        }
        revealChecks(d);
      })
      .catch(function (e) {
        box.innerHTML =
          '<div class="alert alert-fail">诊断请求失败：' + esc(e.message || e) + '</div>' +
          '<button class="btn" style="margin-top:14px" id="retry-diag-btn">重试</button>';
        $('retry-diag-btn').addEventListener('click', step1);
      });
  }

  function revealChecks(data) {
    var list = $('check-list');
    var checks = data.checks;
    list.innerHTML = '';

    checks.forEach(function (c, idx) {
      var item = document.createElement('div');
      item.className = 'check-item';
      item.dataset.status = c.status;

      var expandable = (c.status === 'warn' || c.status === 'fail') && c.fix;
      if (expandable) { item.classList.add('expandable'); }

      var iconChar = STATUS_ICON[c.status] || '?';
      item.innerHTML =
        '<div class="check-icon ' + c.status + '">' + iconChar + '</div>' +
        '<div class="check-body">' +
          '<div class="check-name">' + esc(c.name) +
            '<span class="status-badge ' + c.status + '">' + c.status.toUpperCase() + '</span>' +
          '</div>' +
          '<div class="check-detail">' + esc(c.detail) + '</div>' +
          (expandable ?
            '<div class="check-fix">' +
              '<div class="fix-desc">' + esc(c.fix_desc || '') + '</div>' +
              '<div class="fix-cmd">' +
                '<span>' + esc(c.fix) + '</span>' +
                '<button class="copy-btn" data-copy="' + esc(c.fix) + '">复制</button>' +
              '</div>' +
            '</div>' : '') +
        '</div>';

      if (expandable) {
        item.addEventListener('click', function () {
          item.classList.toggle('expanded');
        });
      }

      list.appendChild(item);

      // 逐项揭晓（每 300ms 一项）
      setTimeout(function () { item.classList.add('show'); }, idx * 300);
    });

    // 全部揭晓后显示总结
    setTimeout(function () { showSummary(data); }, checks.length * 300 + 400);
  }

  // ---------- 步骤 2：总结 ----------
  function showSummary(data) {
    var s = data.summary || {};
    var box = $('wizard-body');

    // 移除等待提示
    var runAlert = box.querySelector('.alert-run');
    if (runAlert) { runAlert.remove(); }

    var summary = document.createElement('div');
    summary.className = 'summary-card';
    summary.innerHTML =
      '<h2 style="color:var(--text-strong);font-size:1.2rem">诊断完成</h2>' +
      '<div class="summary-numbers">' +
        '<div class="summary-num ok"><div class="num">' + (s.ok || 0) + '</div><div class="lbl">OK</div></div>' +
        '<div class="summary-num warn"><div class="num">' + (s.warn || 0) + '</div><div class="lbl">WARN</div></div>' +
        '<div class="summary-num fail"><div class="num">' + (s.fail || 0) + '</div><div class="lbl">FAIL</div></div>' +
      '</div>';

    if ((s.warn || 0) + (s.fail || 0) > 0) {
      var hasWarnFail = data.checks.some(function (c) { return c.status === 'warn' || c.status === 'fail'; });
      if (hasWarnFail) {
        summary.innerHTML += '<p style="color:var(--text-muted);margin-bottom:14px">展开上方的 WARN/FAIL 项查看修复命令，或查看相关文档。</p>';
      }
      summary.innerHTML += '<a class="btn btn-ghost" href="#/docs/faq">查看常见问题</a>';
    } else {
      summary.innerHTML += '<p style="color:var(--ok);margin-bottom:14px;font-weight:600">一切正常！</p>';
    }

    summary.innerHTML += '<button class="btn" style="margin-left:10px" id="re-run-btn">重新诊断</button>';
    box.appendChild(summary);

    $('re-run-btn').addEventListener('click', step0);
    bindCopyButtons();
  }

  function bindCopyButtons() {
    var btns = document.querySelectorAll('.copy-btn');
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener('click', function (e) {
        e.stopPropagation();
        var text = this.getAttribute('data-copy') || '';
        copyText(text).then(function () {
          var orig = this.textContent;
          this.textContent = '已复制';
          var self = this;
          setTimeout(function () { self.textContent = orig; }, 1500);
        }.bind(this));
      });
    }
  }

  window.IPV8_Wizard = {
    start: step0
  };
})();
