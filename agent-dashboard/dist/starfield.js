/** Decorative, dependency-free background inspired by DESIGN.md. */
export function initStarfield(canvas) {
  const context = canvas?.getContext?.('2d', { alpha: false });
  if (!context) return { destroy() {}, setRunning() {} };

  const palette = ['174,246,207', '95,230,160', '234,255,242'];
  const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const atmosphere = document.createElement('canvas');
  const atmosphereContext = atmosphere.getContext('2d', { alpha: false });
  let width = 1;
  let height = 1;
  let ratio = 1;
  let stars = [];
  let frame = 0;
  let lastTime = 0;
  let elapsed = 0;
  let running = false;
  let destroyed = false;
  let rotation = 0;

  canvas.setAttribute('aria-hidden', 'true');

  function makeStar(depth = Math.random()) {
    return {
      x: (Math.random() - 0.5) * 2.6,
      y: (Math.random() - 0.5) * 2.6,
      z: 0.3 + depth * 1.5,
      size: 0.35 + Math.random() * 0.75,
      opacity: 0.1 + Math.random() * 0.25,
      phase: Math.random() * Math.PI * 2,
      tint: Math.floor(Math.random() * palette.length),
    };
  }

  function paintAtmosphere() {
    atmosphere.width = Math.max(1, Math.round(width * ratio));
    atmosphere.height = Math.max(1, Math.round(height * ratio));
    if (!atmosphereContext) return;
    atmosphereContext.setTransform(ratio, 0, 0, ratio, 0, 0);
    atmosphereContext.fillStyle = '#050909';
    atmosphereContext.fillRect(0, 0, width, height);
    const reach = Math.max(width, height) * 0.8;
    const cyan = atmosphereContext.createRadialGradient(0, 0, 0, 0, 0, reach);
    cyan.addColorStop(0, 'rgba(174,233,255,0.045)');
    cyan.addColorStop(0.45, 'rgba(32,88,82,0.022)');
    cyan.addColorStop(1, 'rgba(0,0,0,0)');
    atmosphereContext.fillStyle = cyan;
    atmosphereContext.fillRect(0, 0, width, height);
    const violet = atmosphereContext.createRadialGradient(width, height, 0, width, height, reach);
    violet.addColorStop(0, 'rgba(199,155,255,0.035)');
    violet.addColorStop(1, 'rgba(0,0,0,0)');
    atmosphereContext.fillStyle = violet;
    atmosphereContext.fillRect(0, 0, width, height);
  }

  function draw() {
    context.setTransform(1, 0, 0, 1, 0, 0);
    if (atmosphereContext) context.drawImage(atmosphere, 0, 0);
    else {
      context.fillStyle = '#050909';
      context.fillRect(0, 0, canvas.width, canvas.height);
    }
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    const scale = Math.max(width, height) * 0.55;
    const sine = Math.sin(rotation);
    const cosine = Math.cos(rotation);
    for (const star of stars) {
      const x = width * 0.54 + (star.x * cosine - star.y * sine) * scale / star.z;
      const y = height * 0.46 + (star.x * sine + star.y * cosine) * scale / star.z;
      if (x < -8 || y < -8 || x > width + 8 || y > height + 8) continue;
      const twinkle = motion.matches ? 0.8 : 0.78 + Math.sin(elapsed * 0.7 + star.phase) * 0.22;
      const alpha = Math.min(0.42, star.opacity * twinkle / star.z);
      const radius = Math.min(1.6, star.size / star.z);
      context.fillStyle = `rgba(${palette[star.tint]},${alpha})`;
      context.beginPath();
      context.arc(x, y, radius, 0, Math.PI * 2);
      context.fill();
      if (radius > 1.1) {
        context.fillStyle = `rgba(${palette[star.tint]},${alpha * 0.07})`;
        context.beginPath();
        context.arc(x, y, radius * 3, 0, Math.PI * 2);
        context.fill();
      }
    }
  }

  function tick(now) {
    frame = 0;
    if (destroyed || document.hidden || motion.matches) return;
    if (!lastTime) lastTime = now;
    const difference = now - lastTime;
    if (difference >= 1000 / 30) {
      const dt = Math.min(0.08, difference / 1000);
      lastTime = now;
      elapsed += dt;
      rotation += dt * (running ? 0.008 : 0.003);
      for (const star of stars) {
        star.z -= dt * (running ? 0.045 : 0.012);
        if (star.z <= 0.3) Object.assign(star, makeStar(1));
      }
      draw();
    }
    frame = requestAnimationFrame(tick);
  }

  function syncAnimation() {
    if (frame) cancelAnimationFrame(frame);
    frame = 0;
    lastTime = 0;
    if (destroyed || document.hidden) return;
    draw();
    if (!motion.matches) frame = requestAnimationFrame(tick);
  }

  function resize() {
    if (destroyed) return;
    const bounds = canvas.getBoundingClientRect();
    const nextWidth = Math.max(1, Math.round(bounds.width || window.innerWidth));
    const nextHeight = Math.max(1, Math.round(bounds.height || window.innerHeight));
    const nextRatio = Math.min(2, window.devicePixelRatio || 1);
    if (nextWidth === width && nextHeight === height && nextRatio === ratio && stars.length) return;
    width = nextWidth;
    height = nextHeight;
    ratio = nextRatio;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    const count = Math.max(130, Math.min(450, Math.round(width * height / 3900)));
    stars = Array.from({ length: count }, () => makeStar());
    paintAtmosphere();
    draw();
  }

  const resizeObserver = typeof ResizeObserver === 'function' ? new ResizeObserver(resize) : null;
  resizeObserver?.observe(canvas);
  window.addEventListener('resize', resize, { passive: true });
  document.addEventListener('visibilitychange', syncAnimation);
  if (motion.addEventListener) motion.addEventListener('change', syncAnimation);
  else motion.addListener(syncAnimation);
  resize();
  syncAnimation();

  return {
    setRunning(value) {
      running = Boolean(value);
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      if (frame) cancelAnimationFrame(frame);
      frame = 0;
      resizeObserver?.disconnect();
      window.removeEventListener('resize', resize);
      document.removeEventListener('visibilitychange', syncAnimation);
      if (motion.removeEventListener) motion.removeEventListener('change', syncAnimation);
      else motion.removeListener(syncAnimation);
      stars = [];
      atmosphere.width = 1;
      atmosphere.height = 1;
    },
  };
}
