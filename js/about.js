// About modal: focus trap, Esc-to-close, focus restoration, and
// section-targeted opening (normal About vs. footer Privacy/Data Sources).
const FOCUSABLE = 'a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])';

export function initAboutModal(overlay) {
  const dialog = overlay.querySelector('.modal');
  const closeBtn = overlay.querySelector('[data-modal-close]');
  let lastFocused = null;

  function focusablesIn(node) {
    return Array.from(node.querySelectorAll(FOCUSABLE)).filter((n) => n.offsetParent !== null || n === document.activeElement);
  }

  function onKeydown(e) {
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
      return;
    }
    if (e.key !== 'Tab') return;
    const focusables = focusablesIn(dialog);
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  function open(section, opener) {
    lastFocused = opener || document.activeElement;
    overlay.hidden = false;
    document.body.classList.add('modal-open');
    overlay.addEventListener('keydown', onKeydown);
    const target = section ? overlay.querySelector(`#about-section-${section}`) : null;
    if (target) {
      target.scrollIntoView({ block: 'start' });
    } else {
      dialog.scrollTop = 0;
    }
    (closeBtn || dialog).focus();
  }

  function close() {
    if (overlay.hidden) return;
    overlay.hidden = true;
    document.body.classList.remove('modal-open');
    overlay.removeEventListener('keydown', onKeydown);
    if (lastFocused && document.contains(lastFocused)) lastFocused.focus();
  }

  overlay.addEventListener('mousedown', (e) => {
    // Backdrop clicks must NOT dismiss the modal — only explicit close/Esc do.
    if (e.target === overlay) e.preventDefault();
  });
  if (closeBtn) closeBtn.addEventListener('click', () => close());

  return { open, close };
}
