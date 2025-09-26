// -------- Matrix-esque background (blue) --------
(function matrix() {
  const canvas = document.getElementById('matrixCanvas');
  const ctx = canvas.getContext('2d');

  let w, h, cols, drops, fontSize;
  const glyphs = '01░▒▓█▌▐◼◻◾◽◧◩◰◱◲◳◼◾◽▙▚▞▟';
  const palette = ['#68d7ff', '#3ec7ff', '#15baff', '#0aa7e6', '#0892c7'];

  function resize() {
    w = canvas.width  = window.innerWidth;
    h = canvas.height = window.innerHeight;
    fontSize = Math.max(12, Math.floor(w / 120));
    cols = Math.floor(w / fontSize);
    drops = new Array(cols).fill(0).map(()=>Math.floor(Math.random()*h/fontSize));
    ctx.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`;
  }

  function draw() {
    // fade trail
    ctx.fillStyle = 'rgba(0, 30, 50, 0.12)';
    ctx.fillRect(0, 0, w, h);

    for (let i = 0; i < drops.length; i++) {
      const char = glyphs[Math.floor(Math.random()*glyphs.length)];
      const x = i * fontSize;
      const y = drops[i] * fontSize;

      // light glow
      const color = palette[Math.floor(Math.random()*palette.length)];
      ctx.shadowColor = color;
      ctx.shadowBlur = 8;
      ctx.fillStyle = color;
      ctx.fillText(char, x, y);

      // reset & vary speed
      if (y > h && Math.random() > 0.975) drops[i] = 0;
      drops[i] += (Math.random() * 0.8) + 0.6;
    }
    requestAnimationFrame(draw);
  }

  window.addEventListener('resize', resize);
  resize();
  draw();
})();

// -------- Splash Gate Logic --------
(function gate() {
  const splash = document.getElementById('splash');
  const proceedBtn = document.getElementById('proceedBtn');
  const exitBtn = document.getElementById('exitBtn');
  const createUserBtn = document.getElementById('createUserBtn');
  const resetPwdBtn = document.getElementById('resetPwdBtn');

  // Persist acceptance this session (in-memory), or use sessionStorage to persist across tabs
  let accepted = false;

  function showSplash() {
    splash.style.display = 'grid';
    document.body.style.overflow = 'hidden';
  }
  function hideSplash() {
    splash.style.display = 'none';
    document.body.style.overflow = 'hidden'; // keep cinematic experience
  }

  proceedBtn.addEventListener('click', () => { accepted = true; hideSplash(); });
  exitBtn.addEventListener('click', () => {
    // Try to close, or redirect to a neutral page if window.close is blocked
    try { window.close(); } catch (_) {}
    window.location.href = 'about:blank';
  });

  createUserBtn.addEventListener('click', () => {
    if (!accepted) { showSplash(); return; }
    window.location.href = '/admin'; // Windows Auth-protected
  });

  resetPwdBtn.addEventListener('click', () => {
    if (!accepted) { showSplash(); return; }
    window.location.href = '/selfservice';
  });

  // Show splash immediately on load
  showSplash();
})();
