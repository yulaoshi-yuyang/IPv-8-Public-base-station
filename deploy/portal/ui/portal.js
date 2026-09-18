/* ============================================================
   IPv8+ Portal — 前端逻辑
   hash 路由 / 首页 / 文档中心 / 诊断 / 控制台
   ============================================================ */
(function () {
  'use strict';

  var SELF_ADDR = window.IPV8_SELF || '';

  function $(id) { return document.getElementById(id); }
  function qs(sel, root) { return (root || document).querySelector(sel); }
  function qsa(sel, root) { return (root || document).querySelectorAll(sel); }

  function esc(s) {
    if (s === null || s === undefined) { return ''; }
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function getJSON(url, ok, fail) {
    fetch(url, { cache: 'no-store' })
      .then(function (r) {
        if (!r.ok) { throw new Error('HTTP ' + r.status); }
        return r.json();
      })
      .then(ok)
      .catch(function (e) { if (fail) { fail(e); } });
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

  function setVal(id, v) { var el = $(id); if (el) { el.textContent = v; } }

  // ============================================================
  //  路由
  // ============================================================
  var pages = ['home', 'docs', 'diagnose', 'console'];

  function getRoute() {
    var hash = window.location.hash.replace(/^#/, '');
    if (!hash || hash === '/') { return { page: 'home' }; }
    var parts = hash.replace(/^\//, '').split('/');
    var page = parts[0];
    if (pages.indexOf(page) === -1) { return { page: '404' }; }
    if (page === 'docs') {
      var sub = parts[1] || 'quickstart';
      var valid = ['quickstart', 'cli', 'concepts', 'faq'];
      if (valid.indexOf(sub) === -1) { sub = 'quickstart'; }
      return { page: 'docs', sub: sub };
    }
    return { page: page };
  }

  function showPage(route) {
    // 切换 nav 高亮
    qsa('.nav-link').forEach(function (a) {
      var target = a.getAttribute('data-nav');
      a.classList.toggle('active', target === route.page);
    });

    // 切换 page 容器
    qsa('.page').forEach(function (p) { p.classList.remove('active'); });
    var targetPage = $('page-' + route.page);
    if (targetPage) {
      targetPage.classList.add('active');
    } else {
      $('page-404').classList.add('active');
    }

    window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });

    // 按页面初始化
    if (route.page === 'home') { initHome(); }
    else if (route.page === 'docs') { renderDocs(route.sub); }
    else if (route.page === 'diagnose') { window.IPV8_Wizard.start(); }
    else if (route.page === 'console') { initConsole(); }

    // 离开首页时停止状态面板轮询
    if (route.page !== 'home') { stopNetStatus(); }
  }

  function navigate(hash) {
    window.location.hash = hash;
  }

  function onHashChange() {
    var route = getRoute();
    // 离开控制台时停止跨机互连轮询，避免后台持续请求
    if (route.page !== 'console') { stopPolling(); resetCrossBtn(); }
    showPage(route);
  }

  // ============================================================
  //  首页
  // ============================================================
  var homeInited = false;

  function initHome() {
    if (!homeInited) {
      homeInited = true;
      if (window.IPV8_Topology) { window.IPV8_Topology.init(); }
      initGeo();
      initAddrExplorer();
      initNetStatus();
    }
    // 每次进首页都刷新一次状态面板
    refreshNetStatus();
    startNetStatusTimer();
  }

  // ============================================================
  //  地址结构交互拆解
  // ============================================================
  var ADDR_GROUPS = [
    { name: '协议魔数', hex: 'fb14', desc: '协议标识前缀，固定为 0xFB14，用于在链路上区分 IPv8+ 数据包与其他协议流量。' },
    { name: '区域 ID 高', hex: '0000', desc: '区域 ID（Region）的高 16 位。Region 共 48 位，标识地理/逻辑区域。' },
    { name: '区域 ID 中', hex: '0000', desc: '区域 ID 的中 16 位。' },
    { name: '区域 ID 低', hex: '0001', desc: '区域 ID 的低 16 位。三段组合成 48 位 Region。' },
    { name: '子网 1', hex: '0001', desc: '子网 ID 1（Subnet1），用于在区域内划分子网段。' },
    { name: '子网 2', hex: '0000', desc: '子网 ID 2（Subnet2），进一步细分网络层级。' },
    { name: '节点哈希', hex: '0100', desc: '节点身份哈希（Node Hash），由机器指纹截断派生，标识具体设备。' },
    { name: '会话 ID', hex: '0000', desc: '会话/服务 ID（Session ID），用于 NAT 穿透和临时会话标识，静态地址为 0。' }
  ];

  function initAddrExplorer() {
    var bar = $('addr-bar');
    var detail = $('addr-detail');
    if (!bar || !detail) { return; }

    // 用本机真实地址，否则用默认示例
    var addr = (window.IPV8_SELF || '').split(':');
    var groups = ADDR_GROUPS.slice();
    if (addr.length === 8) {
      for (var i = 0; i < 8; i++) { groups[i] = { name: groups[i].name, hex: addr[i], desc: groups[i].desc }; }
    }

    var html = '';
    for (var i = 0; i < groups.length; i++) {
      html += '<button class="addr-seg" data-idx="' + i + '">' +
        '<span class="seg-hex">' + esc(groups[i].hex) + '</span>' +
        '<span class="seg-name">' + esc(groups[i].name) + '</span>' +
      '</button>';
      if (i < groups.length - 1) { html += '<span class="addr-colon">:</span>'; }
    }
    bar.innerHTML = html;

    function showDetail(idx) {
      var g = groups[idx];
      detail.innerHTML = '<div class="addr-detail-card">' +
        '<span class="addr-detail-label">第 ' + (idx + 1) + ' 段 · ' + esc(g.name) + '</span>' +
        '<code class="addr-detail-hex">' + esc(g.hex) + '</code>' +
        '<p class="addr-detail-desc">' + esc(g.desc) + '</p>' +
      '</div>';
      qsa('.addr-seg').forEach(function (s, j) {
        s.classList.toggle('active', j === idx);
      });
    }

    qsa('.addr-seg').forEach(function (s) {
      s.addEventListener('click', function () {
        showDetail(parseInt(this.getAttribute('data-idx'), 10));
      });
    });
    showDetail(0);
  }

  // ============================================================
  //  网络状态实时面板
  // ============================================================
  var netStatusTimer = null;

  function initNetStatus() {
    // 页面可见性变化时暂停/恢复
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) { stopNetStatus(); }
      else if (getRoute().page === 'home') { refreshNetStatus(); startNetStatusTimer(); }
    });
  }

  function startNetStatusTimer() {
    if (netStatusTimer) { return; }
    netStatusTimer = setInterval(refreshNetStatus, 5000);
  }

  function stopNetStatus() {
    if (netStatusTimer) { clearInterval(netStatusTimer); netStatusTimer = null; }
  }

  function refreshNetStatus() {
    getJSON('/api/status', function (d) {
      setVal('net-status', d.status === 'online' ? '在线' : (d.status || '—'));
      setVal('net-ipv8', d.ipv8 || '—');
      setVal('net-clients', d.clients !== undefined ? d.clients : '—');
      var visa = d.visa || {};
      setVal('net-visa', visa.exists ? '已签发' : '未签发');
      setVal('net-dns', d.dns || '—');
      // 防火墙数据需要另请求
      getJSON('/api/firewall', function (f) {
        setVal('net-fw', (f.winActive || 0) + '/' + (f.winTotal || 0) + ' 启用');
      }, function () {});
    }, function () {
      setVal('net-status', '离线');
    });
  }

  function setVal(id, v) {
    var el = $(id);
    if (el) { el.textContent = (v === null || v === undefined || v === '') ? '—' : v; }
  }

  // GeoIP 查询
  var GEO_ROWS = [
    ['IP 地址', 'ip'], ['协议版本', 'version'], ['国家', 'country'], ['省份', 'province'],
    ['城市', 'city'], ['区县', 'district'], ['邮编', 'zipcode'], ['区号', 'areacode'],
    ['ISP', 'isp'], ['ASN', 'asn'], ['组织', 'organization'], ['纬度', 'latitude'],
    ['经度', 'longitude'], ['用途', 'purpose'], ['操作者', 'operator'],
    ['网络类型', 'network_type'], ['备注', 'notes']
  ];

  function isValidIPv8(addr) {
    // 支持 8 段完整形式，或 :: 压缩形式，或纯 32 位 hex
    if (/^[0-9a-fA-F:]+$/.test(addr) === false) { return false; }
    if (addr.indexOf(':') === -1 && addr.length === 32) { return true; }
    var segs = addr.split(':');
    if (segs.length > 8) { return false; }
    for (var i = 0; i < segs.length; i++) {
      if (segs[i] === '') { continue; } // :: 压缩
      if (!/^[0-9a-fA-F]{1,4}$/.test(segs[i])) { return false; }
    }
    return true;
  }

  function lookupGeo() {
    var box = $('geo-result');
    var input = $('geo-input');
    if (!box || !input) { return; }
    var ip = (input.value || '').trim();

    if (ip && !isValidIPv8(ip)) {
      input.classList.add('invalid');
      box.innerHTML = '<div class="geo-empty">地址格式非法。示例：<code>fb14:0000:0000:0001:0001:0000:0100:0000</code></div>';
      return;
    }
    input.classList.remove('invalid');

    box.innerHTML = '<div class="alert alert-run">查询中…</div>';
    getJSON('/api/geoip?ip=' + encodeURIComponent(ip), function (d) {
      if (d.error && !d.country) {
        box.innerHTML = '<div class="geo-empty">未收录号段：<span class="mono">' + esc(d.ip || ip) + '</span></div>';
        return;
      }
      var isSelf = SELF_ADDR && d.ip && d.ip === SELF_ADDR;
      var rows = '';
      for (var i = 0; i < GEO_ROWS.length; i++) {
        var label = GEO_ROWS[i][0];
        var raw = d[GEO_ROWS[i][1]];
        var val = (raw === null || raw === undefined || raw === '' || raw === '-') ? '—' : raw;
        rows += '<div class="geo-item"><div class="label">' + esc(label) + '</div><div class="value">' + esc(val) + '</div></div>';
      }
      box.innerHTML =
        '<div class="geo-card">' +
          '<div class="geo-card-head">' +
            '<span class="geo-card-addr">' + esc(d.ip || ip) + '</span>' +
            (isSelf ? '<span class="self-mark">● 这是你的地址</span>' : '') +
          '</div>' +
          '<div class="geo-grid">' + rows + '</div>' +
        '</div>';
    }, function (e) {
      box.innerHTML = '<div class="alert alert-fail">请求失败：' + esc(e.message || e) + '</div>';
    });
  }

  function initGeo() {
    var btn = $('geo-btn'), input = $('geo-input');
    if (btn) { btn.addEventListener('click', lookupGeo); }
    if (input) {
      input.addEventListener('keydown', function (e) { if (e.key === 'Enter') { lookupGeo(); } });
      input.addEventListener('input', function () { input.classList.remove('invalid'); });
    }
  }

  // ============================================================
  //  文档中心
  // ============================================================
  var DOCS_NAV = [
    { id: 'quickstart', title: '快速开始' },
    { id: 'cli', title: '命令参考' },
    { id: 'concepts', title: '概念科普' },
    { id: 'faq', title: '常见问题' }
  ];

  function renderDocs(sub) {
    var docs = window.IPV8_DOCS || {};
    var data = docs[sub];
    var sidebar = $('docs-sidebar');
    var content = $('docs-content');
    var toc = $('docs-toc');

    if (!data) { return; }

    // 左侧导航
    var navHtml = '';
    DOCS_NAV.forEach(function (n) {
      navHtml += '<button class="docs-nav-item' + (n.id === sub ? ' active' : '') +
        '" data-doc="' + n.id + '">' + esc(n.title) + '</button>';
    });
    sidebar.innerHTML = navHtml;
    qsa('.docs-nav-item').forEach(function (b) {
      b.addEventListener('click', function () {
        navigate('/docs/' + this.getAttribute('data-doc'));
      });
    });

    // 正文
    var bodyHtml = '<h1>' + esc(data.title) + '</h1>' +
      '<p class="doc-lead">' + renderInline(data.lead || '') + '</p>';

    (data.sections || []).forEach(function (sec) {
      bodyHtml += '<h2 id="' + esc(sec.id) + '">' + esc(sec.title) + '</h2>';
      (sec.body || []).forEach(function (block) {
        bodyHtml += renderBlock(block);
      });
      if (sec.terms) {
        sec.terms.forEach(function (t) {
          bodyHtml += makeTermBlock(t.prompt, t.comment);
        });
      }
    });

    content.innerHTML = bodyHtml;

    // 右侧目录（不能用 href="#xxx"：hash 会被路由当成页面跳转而显示 404）
    var tocHtml = '<div class="docs-toc-title">本页目录</div>';
    (data.sections || []).forEach(function (sec) {
      tocHtml += '<a href="#" data-anchor="' + esc(sec.id) + '">' + esc(sec.title) + '</a>';
    });
    toc.innerHTML = tocHtml;
    qsa('.docs-toc a').forEach(function (a) {
      a.addEventListener('click', function (e) {
        e.preventDefault();
        var target = document.getElementById(this.getAttribute('data-anchor'));
        if (target) { target.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
      });
    });

    // 绑定复制按钮
    bindCopyButtons();
  }

  function renderBlock(block) {
    switch (block.type) {
      case 'p':
        return '<p>' + renderInline(block.text) + '</p>';
      case 'ul':
        return '<ul>' + block.items.map(function (i) { return '<li>' + renderInline(i) + '</li>'; }).join('') + '</ul>';
      case 'ol':
        return '<ol>' + block.items.map(function (i) { return '<li>' + renderInline(i) + '</li>'; }).join('') + '</ol>';
      case 'code':
        return '<div class="term-block"><div class="term-head"><div class="term-dots"><span></span><span></span><span></span></div></div><div class="term-body">' + esc(block.text) + '</div></div>';
      case 'table':
        var thead = '<tr>' + block.headers.map(function (h) { return '<th>' + esc(h) + '</th>'; }).join('') + '</tr>';
        var tbody = block.rows.map(function (r) {
          return '<tr>' + r.map(function (c, i) {
            return '<td' + (i === 0 ? ' class="cmd"' : '') + '>' + renderInline(c) + '</td>';
          }).join('') + '</tr>';
        }).join('');
        return '<div style="overflow-x:auto"><table class="cmd-table"><thead>' + thead + '</thead><tbody>' + tbody + '</tbody></table></div>';
      default:
        return '';
    }
  }

  function renderInline(text) {
    // 转义后还原 <code>...</code>
    var escaped = esc(text);
    return escaped.replace(/&lt;code&gt;([\s\S]*?)&lt;\/code&gt;/g, '<code>$1</code>');
  }

  function makeTermBlock(cmd, comment) {
    return '<div class="term-block">' +
      '<div class="term-head"><div class="term-dots"><span></span><span></span><span></span></div>' +
      '<button class="copy-btn" data-copy="' + esc(cmd) + '">复制</button></div>' +
      '<div class="term-body"><span class="prompt">$</span> ' + esc(cmd) +
      (comment ? ' <span class="comment"># ' + esc(comment) + '</span>' : '') + '</div></div>';
  }

  function bindCopyButtons() {
    var btns = document.querySelectorAll('.copy-btn');
    for (var i = 0; i < btns.length; i++) {
      if (btns[i].dataset.bound) { continue; }
      btns[i].dataset.bound = '1';
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

  // ============================================================
  //  控制台（收纳旧管理功能）
  // ============================================================
  var consoleInited = false;
  // 本地 9100 客户端是否在线：在线时本机信息以客户端为准，
  // 门户 /api/firewall 的签证字段不得覆盖（两边语义/时效不同）
  var localClientOnline = false;

  function initConsole() {
    // 事件只绑定一次；数据每次进入页面都刷新，避免切走再回来看到旧状态
    if (!consoleInited) {
      consoleInited = true;
      initCross();
      initFirewall();
    }
    localClientOnline = false;
    var ipBox = $('cross-my-ip');
    if (ipBox) { ipBox.textContent = '获取中…'; }
    loadConsoleInfo();
  }

  // 渲染本机 IP（跨机互连卡片）；两条地址分行显示，避免首尾粘连
  function renderMyIp(ipv6, ipv4) {
    var box = $('cross-my-ip');
    if (!box) { return; }
    var html = '';
    if (ipv6) { html += '<span class="mono ip-line">' + esc(ipv6) + '</span>'; }
    if (ipv4) { html += '<span class="mono ip-line">' + esc(ipv4) + '</span>'; }
    box.innerHTML = html || '<span style="color:var(--fail)">未检测到可用 IP</span>';
  }

  // 本机客户端不可达时，回落门户接口取服务器视角的 IP
  function loadMyIpFromPortal() {
    getJSON('/api/my-ip', function (d) {
      renderMyIp(d.ipv6, d.ipv4);
    }, function () {
      var box = $('cross-my-ip');
      if (box) { box.innerHTML = '<span style="color:var(--text-faint)">获取 IP 失败</span>'; }
    });
  }

  // 已连接客户端
  function loadClients() {
    var box = $('console-clients-body');
    if (!box) { return; }
    getJSON('/api/clients', function (d) {
      var total = d.total || 0;
      var active = d.active || 0;
      box.innerHTML =
        '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:14px">' +
          '<div class="info-item"><div class="label">已分配</div><div class="value" style="font-size:1.4rem">' + total + '</div></div>' +
          '<div class="info-item"><div class="label">在线</div><div class="value" style="font-size:1.4rem;color:var(--ok)">' + active + '</div></div>' +
        '</div>' +
        '<div class="alert alert-idle" style="font-size:.82rem;margin:0">' +
          '客户端详细信息（IPv8 地址、主机名等）不在公共页面展示。<br>' +
          '如需查看本机状态，请运行 <code>ping8 diagnose</code> 或使用顶部「诊断」向导。' +
        '</div>';
    }, function () {
      box.innerHTML = '<div style="text-align:center;color:var(--fail);padding:20px">加载失败</div>';
    });
  }

  // 本机客户端信息（先本地后服务器）
  function loadConsoleInfo() {
    // 已连接客户端
    loadClients();

    // 版本号（服务器和客户端都从 /api/ping8-version 取）
    getJSON('/api/ping8-version', function (d) {
      setVal('cli-version', 'v' + (d.version || '?'));
    }, function () {});

    // 本机信息：先试本地 serve
    fetch('http://127.0.0.1:9100/api/status', { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error(); return r.json(); })
      .then(function (d) {
        localClientOnline = true;
        renderLocalInfo(d, true);
      })
      .catch(function () {
        // 回落服务器 /api/status
        getJSON('/api/status', function (d) {
          renderLocalInfo(d, false);
        }, function () {
          renderLocalInfo(null, false);
        });
      });

    // 防火墙信息（含签证状态）
    getJSON('/api/firewall', function (d) {
      renderFirewall(d);
    }, function () {});
  }

  function renderLocalInfo(d, isLocal) {
    var badge = $('cli-source-badge');
    if (badge) {
      if (isLocal) { badge.innerHTML = '<span class="badge badge-ok">本机客户端</span>'; }
      else { badge.innerHTML = '<span class="badge badge-no-dot badge-brand">服务器端</span>'; }
    }
    if (!d) { if (!isLocal) { loadMyIpFromPortal(); } return; }
    var visa = d.visa || {};
    setVal('cli-ipv8', visa.addr || d.ipv8 || '-');
    setVal('cli-ipv6', d.ipv6 || '未检测到');
    setVal('cli-dns', d.dns || '-');

    var visaExists = visa.exists !== undefined ? visa.exists : (d.visa_exists);
    var caExists = d.ca_exists;
    var caLabel = $('srv-ca-label');

    if (isLocal) {
      // 9100 的 ca_exists 表示本机存在 CA 种子（可签发签证）；
      // 门户服务器视角的 caExists 只表示 ca.pub 文件，两者不是一回事
      if (caLabel) { caLabel.textContent = 'CA 签发能力'; }
      setVal('srv-visa-exists', visaExists ? '已签发' : '未签发');
      setVal('srv-ca-exists', caExists ? '本机 CA' : '未配置');
      // 跨机互连的本机 IP 也以客户端实时探测为准
      renderMyIp(d.ipv6, d.ipv4);
    } else {
      if (caLabel) { caLabel.textContent = 'CA 公钥'; }
      setVal('srv-visa-exists', visaExists ? '已签发' : '未签发');
      setVal('srv-ca-exists', caExists ? '已配置' : '未配置');
      loadMyIpFromPortal();
    }
  }

  function renderFirewall(d) {
    setVal('fw-total', d.winTotal || 0);
    setVal('fw-active', d.winActive || 0);
    setVal('fw-clients', d.clientCount || 0);

    // 服务器回退时，签证信息来自 /api/firewall；
    // 本地客户端在线时其数据更准（且 ca 语义不同），不得覆盖
    if (!localClientOnline) {
      var visa = d.visa || {};
      if (visa.exists !== undefined) {
        setVal('srv-visa-exists', visa.exists ? '已签发' : '未签发');
      }
      if (visa.caExists !== undefined) {
        setVal('srv-ca-exists', visa.caExists ? '已配置' : '未配置');
      }
    }

    var rulesBody = $('fw-rules-body');
    if (rulesBody) {
      var rules = d.winRules || [];
      if (!rules.length) {
        rulesBody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-faint);padding:20px">暂无系统防火墙规则</td></tr>';
      } else {
        var PROFILE_MAP = { Any: '任意', Domain: '域', Private: '专用', Public: '公用' };
        var rows = rules.map(function (r) {
          // 后端可能返回数字 1/2 或英文字符串，两种都兼容
          var dirNum = Number(r.Direction);
          var dir = (dirNum === 1 || r.Direction === 'Inbound') ? '入站'
            : (dirNum === 2 || r.Direction === 'Outbound') ? '出站' : '未知';
          var prof = String(r.Profile || '-').split(/,\s*/).map(function (p) {
            return (PROFILE_MAP[p] !== undefined) ? PROFILE_MAP[p] : p;
          }).join('+');
          var st = r.Enabled
            ? '<span class="badge badge-ok">启用</span>'
            : '<span class="badge badge-warn">禁用</span>';
          return '<tr><td class="mono">' + esc(r.DisplayName || '-') + '</td><td>' + dir + '</td><td>' + st + '</td><td>' + esc(prof) + '</td></tr>';
        }).join('');
        rulesBody.innerHTML = rows;
      }
    }
  }

  // 跨机互连
  var pollTimer = null;

  function crossStatus(msg, cls) {
    var el = $('cross-status');
    if (el) { el.innerHTML = '<div class="alert ' + cls + '">' + msg + '</div>'; }
  }

  function crossResult(text) {
    var el = $('cross-result');
    if (!el) { return; }
    if (!text) { el.innerHTML = ''; return; }
    el.innerHTML = '<div class="term-block"><div class="term-body">' + esc(text) + '</div></div>';
  }

  function resetCrossBtn(label) {
    var btn = $('cross-start-btn');
    if (btn) { btn.disabled = false; btn.textContent = label || '发送信任请求'; }
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  function startCrossTest() {
    var ipEl = $('cross-peer-ip'), portEl = $('cross-peer-port');
    var ip = (ipEl.value || '').trim();
    var port = (portEl.value || '').trim() || '45801';

    if (!ip) {
      crossStatus('请先填写对端机器 IP 地址', 'alert-fail');
      return;
    }

    var btn = $('cross-start-btn');
    if (!btn) { return; }
    btn.disabled = true;
    btn.textContent = '发送中…';
    crossResult('');
    crossStatus('正在向 ' + esc(ip) + ':' + esc(port) + ' 发送信任请求…', 'alert-run');

    getJSON('/api/cross-test?ip=' + encodeURIComponent(ip) + '&port=' + encodeURIComponent(port),
      function (d) {
        if (d.status === 'running') {
          crossStatus('信任请求已发送，等待对端在 CMD 中确认（15秒超时）…', 'alert-run');
          stopPolling();
          pollTimer = setInterval(pollCrossStatus, 2000);
        } else if (d.error) {
          crossStatus('错误：' + esc(d.error), 'alert-fail');
          resetCrossBtn();
        } else {
          crossStatus('未知响应', 'alert-idle');
          resetCrossBtn();
        }
      },
      function (e) {
        crossStatus('请求失败：' + esc(e.message || e), 'alert-fail');
        resetCrossBtn();
      });
  }

  function pollCrossStatus() {
    getJSON('/api/cross-test-status', function (s) {
      if (s.status === 'running') {
        crossStatus('等待对端确认 · ' + esc(s.elapsed) + 's', 'alert-run');
        return;
      }
      stopPolling();
      if (s.status === 'pass') {
        crossStatus('对端已同意！隧道连接已建立', 'alert-ok');
        crossResult('现在可以使用 ping8 ping 互相测试连通性');
      } else if (s.status === 'fail') {
        crossStatus('对端拒绝或请求超时', 'alert-fail');
        crossResult('请确认对端已运行 ping8 trust listen');
      } else {
        crossStatus('请求已结束', 'alert-idle');
      }
      resetCrossBtn();
    }, function () {});
  }

  function initCross() {
    var btn = $('cross-start-btn');
    if (btn) { btn.addEventListener('click', startCrossTest); }
    var ipEl = $('cross-peer-ip');
    if (ipEl) {
      ipEl.addEventListener('keydown', function (e) { if (e.key === 'Enter') { startCrossTest(); } });
    }
  }

  // 防火墙操作
  function firewallAction(action, btn) {
    var box = $('firewall-result');
    if (btn) { btn.disabled = true; }
    box.innerHTML = '<div class="alert alert-run">正在执行…</div>';

    getJSON('/api/firewall?action=' + encodeURIComponent(action), function (d) {
      var lines = d.result || [];
      if (lines.length) {
        box.innerHTML = '<div class="alert alert-ok">' + (Array.isArray(lines) ? lines.map(esc).join('<br>') : esc(lines)) + '</div>';
        setTimeout(function () { box.innerHTML = ''; }, 3000);
      } else {
        box.innerHTML = '';
      }
      // 只刷新受影响的两块，避免把本机信息/版本/IP 等无关请求全部重发
      loadClients();
      getJSON('/api/firewall', renderFirewall, function () {});
      if (btn) { btn.disabled = false; }
    }, function (e) {
      box.innerHTML = '<div class="alert alert-fail">错误：' + esc(e.message || e) + '</div>';
      if (btn) { btn.disabled = false; }
    });
  }

  function initFirewall() {
    var btns = document.querySelectorAll('[data-fw]');
    for (var i = 0; i < btns.length; i++) {
      (function (b) {
        b.addEventListener('click', function () { firewallAction(b.getAttribute('data-fw'), b); });
      })(btns[i]);
    }
    var refreshBtn = $('fw-refresh-btn');
    if (refreshBtn) { refreshBtn.addEventListener('click', loadConsoleInfo); }
  }

  // ============================================================
  //  启动
  // ============================================================
  function boot() {
    // nav 点击
    qsa('.nav-link').forEach(function (a) {
      a.addEventListener('click', function () {
        var target = this.getAttribute('data-nav');
        if (target === 'home') { navigate('/'); }
        else { navigate('/' + target); }
      });
    });

    window.addEventListener('hashchange', onHashChange);
    showPage(getRoute());
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
