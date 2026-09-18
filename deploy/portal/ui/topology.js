/* ============================================================
   IPv8+ 动态拓扑背景
   节点漂移 + 连线 + 数据包光点流动
   独立可卸载，离开视口自动暂停
   ============================================================ */
(function () {
  'use strict';

  var canvas = null;
  var ctx = null;
  var dpr = 1;
  var nodes = [];
  var packets = [];
  var animId = null;
  var running = false;
  var mouse = { x: -9999, y: -9999, active: false };
  var observer = null;
  var resizeObserver = null;
  var host = null;

  var CONFIG = {
    nodeCount: 36,
    nodeRadius: 1.8,
    linkDistance: 130,
    linkMaxDistance: 160,
    driftSpeed: 0.25,
    mouseRadius: 140,
    packetInterval: 1800, // ms
    packetSpeed: 1.6
  };

  function createNode(w, h) {
    return {
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * CONFIG.driftSpeed,
      vy: (Math.random() - 0.5) * CONFIG.driftSpeed,
      r: CONFIG.nodeRadius + Math.random() * 0.8
    };
  }

  function init() {
    canvas = document.getElementById('topology-canvas');
    if (!canvas) { return; }
    ctx = canvas.getContext('2d');
    dpr = window.devicePixelRatio || 1;

    // 延迟到下一帧，确保 hero 布局完成后再取尺寸
    requestAnimationFrame(function () {
      resize();
      initNodes();
      start();
    });

    window.addEventListener('resize', onResize);
    // canvas 自身 pointer-events:none，事件永远收不到；绑到父容器 .hero 上
    host = canvas.parentElement;
    if (host) {
      host.addEventListener('mousemove', onMouseMove);
      host.addEventListener('mouseleave', onMouseLeave);
    }

    // ResizeObserver：hero 尺寸变化时重算
    if ('ResizeObserver' in window) {
      resizeObserver = new ResizeObserver(onResize);
      resizeObserver.observe(canvas);
    }

    // IntersectionObserver：离开视口暂停
    if ('IntersectionObserver' in window) {
      observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) { start(); }
          else { stop(); }
        });
      }, { threshold: 0.05 });
      observer.observe(canvas);
    }
  }

  var lastW = 0, lastH = 0;
  function onResize() {
    resize();
    if (!canvas) { return; }
    var rect = canvas.getBoundingClientRect();
    if (Math.abs(rect.width - lastW) > 10 || Math.abs(rect.height - lastH) > 10) {
      lastW = rect.width;
      lastH = rect.height;
      initNodes();
    }
  }

  function resize() {
    if (!canvas || !ctx) { return; }
    var rect = canvas.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) { return; }
    canvas.width = Math.floor(rect.width * dpr);
    canvas.height = Math.floor(rect.height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function initNodes() {
    if (!canvas) { return; }
    var rect = canvas.getBoundingClientRect();
    nodes = [];
    for (var i = 0; i < CONFIG.nodeCount; i++) {
      nodes.push(createNode(rect.width, rect.height));
    }
  }

  function onMouseMove(e) {
    var rect = canvas.getBoundingClientRect();
    mouse.x = e.clientX - rect.left;
    mouse.y = e.clientY - rect.top;
    mouse.active = true;
  }

  function onMouseLeave() {
    mouse.active = false;
    mouse.x = -9999;
    mouse.y = -9999;
  }

  function start() {
    if (running) { return; }
    running = true;
    loop();
  }

  function stop() {
    running = false;
    if (animId) { cancelAnimationFrame(animId); animId = null; }
  }

  var lastPacketTime = 0;

  function loop(t) {
    if (!running) { return; }
    animId = requestAnimationFrame(loop);
    if (!ctx) { return; }

    var rect = canvas.getBoundingClientRect();
    var w = rect.width, h = rect.height;

    ctx.clearRect(0, 0, w, h);

    // 更新节点位置
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      n.x += n.vx;
      n.y += n.vy;

      // 鼠标吸引
      if (mouse.active) {
        var dx = mouse.x - n.x;
        var dy = mouse.y - n.y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONFIG.mouseRadius && dist > 0) {
          var force = (1 - dist / CONFIG.mouseRadius) * 0.4;
          n.x += (dx / dist) * force;
          n.y += (dy / dist) * force;
        }
      }

      // 边界回弹
      if (n.x < 0 || n.x > w) { n.vx *= -1; n.x = Math.max(0, Math.min(w, n.x)); }
      if (n.y < 0 || n.y > h) { n.vy *= -1; n.y = Math.max(0, Math.min(h, n.y)); }
    }

    // 绘制连线
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        var a = nodes[i], b = nodes[j];
        var dx = a.x - b.x, dy = a.y - b.y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONFIG.linkMaxDistance) {
          var alpha = (1 - dist / CONFIG.linkMaxDistance) * 0.25;
          // 鼠标邻近增亮
          if (mouse.active) {
            var midX = (a.x + b.x) / 2, midY = (a.y + b.y) / 2;
            var mdx = mouse.x - midX, mdy = mouse.y - midY;
            var mdist = Math.sqrt(mdx * mdx + mdy * mdy);
            if (mdist < CONFIG.mouseRadius) {
              alpha += (1 - mdist / CONFIG.mouseRadius) * 0.4;
            }
          }
          ctx.strokeStyle = 'rgba(34, 211, 238, ' + Math.min(alpha, 0.7) + ')';
          ctx.lineWidth = 0.6;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    // 绘制节点
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(129, 140, 248, 0.7)';
      ctx.fill();
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + 3, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(34, 211, 238, 0.08)';
      ctx.fill();
    }

    // 生成数据包
    if (t && (t - lastPacketTime) > CONFIG.packetInterval) {
      lastPacketTime = t;
      spawnPacket();
    }

    // 更新绘制数据包
    for (var i = packets.length - 1; i >= 0; i--) {
      var p = packets[i];
      p.progress += CONFIG.packetSpeed / p.totalDist;
      if (p.progress >= 1) {
        packets.splice(i, 1);
        continue;
      }
      var px = p.from.x + (p.to.x - p.from.x) * p.progress;
      var py = p.from.y + (p.to.y - p.from.y) * p.progress;

      // 尾迹
      var tailLen = 0.15;
      var tailStart = Math.max(0, p.progress - tailLen);
      var tx = p.from.x + (p.to.x - p.from.x) * tailStart;
      var ty = p.from.y + (p.to.y - p.from.y) * tailStart;
      var grad = ctx.createLinearGradient(tx, ty, px, py);
      grad.addColorStop(0, 'rgba(34, 211, 238, 0)');
      grad.addColorStop(1, 'rgba(34, 211, 238, 0.9)');
      ctx.strokeStyle = grad;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(tx, ty);
      ctx.lineTo(px, py);
      ctx.stroke();

      // 光点
      ctx.beginPath();
      ctx.arc(px, py, 2.2, 0, Math.PI * 2);
      ctx.fillStyle = '#22d3ee';
      ctx.shadowColor = '#22d3ee';
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  function spawnPacket() {
    if (nodes.length < 2) { return; }
    // 找一条存在的连线（距离 < linkMaxDistance）
    var pairs = [];
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        var dx = nodes[i].x - nodes[j].x;
        var dy = nodes[i].y - nodes[j].y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONFIG.linkMaxDistance) {
          pairs.push({ from: nodes[i], to: nodes[j], dist: dist });
        }
      }
    }
    if (pairs.length === 0) { return; }
    var pair = pairs[Math.floor(Math.random() * pairs.length)];
    packets.push({
      from: pair.from,
      to: pair.to,
      totalDist: pair.dist,
      progress: 0
    });
  }

  // 暴露卸载接口
  window.IPV8_Topology = {
    init: init,
    destroy: function () {
      stop();
      if (observer) { observer.disconnect(); observer = null; }
      if (resizeObserver) { resizeObserver.disconnect(); resizeObserver = null; }
      window.removeEventListener('resize', onResize);
      if (host) {
        host.removeEventListener('mousemove', onMouseMove);
        host.removeEventListener('mouseleave', onMouseLeave);
        host = null;
      }
      nodes = [];
      packets = [];
    }
  };
})();
