const menuToggle = document.querySelector('.menu-toggle');
const navigation = document.querySelector('#site-nav');
const siteHeader = document.querySelector('.site-header');

if (menuToggle && navigation) {
  const mobileViewport = window.matchMedia('(max-width: 900px)');
  const menuLabel = menuToggle.querySelector('.menu-label');
  menuToggle.hidden = false;
  document.documentElement.classList.add('js-ready');

  const setMenuOpen = (requestedOpen, restoreFocus = false) => {
    const isOpen = mobileViewport.matches && requestedOpen;
    if (restoreFocus) menuToggle.focus();
    menuToggle.setAttribute('aria-expanded', String(isOpen));
    navigation.classList.toggle('is-open', isOpen);
    navigation.inert = mobileViewport.matches && !isOpen;
    if (mobileViewport.matches) {
      navigation.setAttribute('aria-hidden', String(!isOpen));
    } else {
      navigation.removeAttribute('aria-hidden');
    }
    if (menuLabel) menuLabel.textContent = isOpen ? 'Close' : 'Menu';
  };

  menuToggle.addEventListener('click', () => {
    setMenuOpen(menuToggle.getAttribute('aria-expanded') !== 'true');
  });

  navigation.addEventListener('click', (event) => {
    const link = event.target.closest('a');
    if (!link) return;
    const wasOpen = menuToggle.getAttribute('aria-expanded') === 'true';
    setMenuOpen(false);
    if (wasOpen && !event.ctrlKey && !event.metaKey && !event.altKey && !event.shiftKey) {
      const section = document.getElementById(link.hash.slice(1));
      const heading = section?.querySelector('h2');
      if (heading) {
        event.preventDefault();
        if (window.location.hash !== link.hash) window.history.pushState(null, '', link.hash);
        heading.focus({ preventScroll: true });
        section.scrollIntoView({ block: 'start' });
      }
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && menuToggle.getAttribute('aria-expanded') === 'true') {
      event.preventDefault();
      setMenuOpen(false, true);
    }
  });

  document.addEventListener('pointerdown', (event) => {
    if (menuToggle.getAttribute('aria-expanded') === 'true' && !siteHeader?.contains(event.target)) {
      setMenuOpen(false);
    }
  });

  siteHeader?.addEventListener('focusout', (event) => {
    if (event.relatedTarget && !siteHeader.contains(event.relatedTarget)) setMenuOpen(false);
  });

  mobileViewport.addEventListener('change', () => {
    const needsFocus = mobileViewport.matches && navigation.contains(document.activeElement);
    setMenuOpen(false, needsFocus);
  });
  window.addEventListener('hashchange', () => setMenuOpen(false));
  setMenuOpen(false);

  const sectionLinks = [...navigation.querySelectorAll('a[href^="#"]')];
  const sections = [...document.querySelectorAll('main > section')];
  let activeSectionId = null;
  const setActiveSection = (sectionId) => {
    if (sectionId === activeSectionId) return;
    activeSectionId = sectionId;
    for (const link of sectionLinks) {
      if (link.hash === `#${sectionId}`) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    }
  };

  setActiveSection(window.location.hash.slice(1));
  window.addEventListener('hashchange', () => setActiveSection(window.location.hash.slice(1)));
  const updateActiveSection = () => {
    if (window.scrollY > 0 && window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 2) {
      setActiveSection('contact');
      return;
    }
    const readingPosition = (siteHeader?.getBoundingClientRect().bottom ?? 0) + 32;
    let currentSectionId = '';
    for (const section of sections) {
      if (section.getBoundingClientRect().top <= readingPosition) currentSectionId = section.id;
    }
    setActiveSection(currentSectionId);
  };

  let scrollUpdatePending = false;
  window.addEventListener('scroll', () => {
    if (scrollUpdatePending) return;
    scrollUpdatePending = true;
    window.requestAnimationFrame(() => {
      updateActiveSection();
      scrollUpdatePending = false;
    });
  }, { passive: true });
  window.addEventListener('resize', updateActiveSection);
  updateActiveSection();
}

for (const carousel of document.querySelectorAll('[data-carousel]')) {
  const track = carousel.querySelector('[data-carousel-track]');
  const allSlides = [...carousel.querySelectorAll('[data-carousel-slide]')];
  let slides = allSlides;
  const controls = carousel.querySelector('.carousel-controls');
  const previous = carousel.querySelector('[data-carousel-prev]');
  const next = carousel.querySelector('[data-carousel-next]');
  const status = carousel.querySelector('[data-carousel-status]');
  if (!track || !slides.length || !controls || !previous || !next || !status) continue;
  controls.hidden = false;

  const visibleRange = () => {
    const bounds = track.getBoundingClientRect();
    const fullyVisible = slides.map((slide, index) => ({ index, bounds: slide.getBoundingClientRect() })).filter((slide) => slide.bounds.left >= bounds.left - 3 && slide.bounds.right <= bounds.right + 3);
    if (fullyVisible.length) return [fullyVisible[0].index, fullyVisible[fullyVisible.length - 1].index];
    const nearest = slides.reduce((best, slide, index) => Math.abs(slide.getBoundingClientRect().left - bounds.left) < Math.abs(slides[best].getBoundingClientRect().left - bounds.left) ? index : best, 0);
    return [nearest, nearest];
  };

  const updateControls = () => {
    previous.disabled = track.scrollLeft <= 2;
    next.disabled = track.scrollLeft >= track.scrollWidth - track.clientWidth - 2;
  };

  const updateStatus = () => {
    const [first, last] = visibleRange();
    const label = first === last ? `${first + 1} / ${slides.length}` : `${first + 1}–${last + 1} / ${slides.length}`;
    if (status.textContent !== label) status.textContent = label;
    updateControls();
  };

  const goTo = (index) => {
    const target = slides[Math.max(0, Math.min(slides.length - 1, index))];
    const offset = target.getBoundingClientRect().left - track.getBoundingClientRect().left;
    track.scrollTo({ left: track.scrollLeft + offset });
  };

  const advance = (direction) => {
    const [first, last] = visibleRange();
    goTo(first + direction * (last - first + 1));
  };

  previous.addEventListener('click', () => advance(-1));
  next.addEventListener('click', () => advance(1));
  track.addEventListener('keydown', (event) => {
    if (event.target !== track || event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
      event.preventDefault();
      advance(event.key === 'ArrowLeft' ? -1 : 1);
    } else if (event.key === 'Home' || event.key === 'End') {
      event.preventDefault();
      goTo(event.key === 'Home' ? 0 : slides.length - 1);
    }
  });

  let settleTimer;
  track.addEventListener('scroll', () => {
    updateControls();
    window.clearTimeout(settleTimer);
    settleTimer = window.setTimeout(updateStatus, 140);
  }, { passive: true });
  window.addEventListener('resize', updateStatus);

  const filters = carousel.querySelector('.credential-filters');
  const filterButtons = [...carousel.querySelectorAll('[data-credential-filter]')];
  const filterSummary = carousel.querySelector('[data-credential-summary]');
  if (filters && filterButtons.length && filterSummary) {
    filters.hidden = false;
    for (const button of filterButtons) {
      button.addEventListener('click', () => {
        const category = button.dataset.credentialFilter;
        for (const filterButton of filterButtons) filterButton.setAttribute('aria-pressed', String(filterButton === button));
        slides = allSlides.filter(slide => category === 'all' || slide.dataset.credentialCategory === category);
        for (const slide of allSlides) slide.hidden = !slides.includes(slide);
        slides.forEach((slide, index) => slide.setAttribute('aria-label', `${index + 1} of ${slides.length}`));
        track.scrollTo({ left: 0, behavior: 'instant' });
        window.clearTimeout(settleTimer);
        const label = button.childNodes[0].textContent.trim();
        filterSummary.textContent = `${label === 'All' ? 'All credentials' : label} · ${slides.length} ${slides.length === 1 ? 'record' : 'records'}`;
        updateStatus();
      });
    }
  }
  updateStatus();
}

const copyButton = document.querySelector('#copy-email');
const copyStatus = document.querySelector('#copy-status');

if (copyButton && copyStatus && navigator.clipboard && window.isSecureContext) {
  copyButton.hidden = false;
  copyButton.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText('btayl106@charlotte.edu');
      copyStatus.textContent = 'Email address copied.';
    } catch {
      copyStatus.textContent = 'Please select the email address to copy it, or use the email link.';
    }
  });
}


/* Chronological archive: accessible category and text filtering, with year markers. */
const timeline = document.querySelector('#career-timeline');
if (timeline) {
  const cards = [...timeline.querySelectorAll('.timeline-entry')];
  const filters = [...document.querySelectorAll('[data-timeline-filter]')];
  const search = document.querySelector('#timeline-search');
  const empty = document.querySelector('#timeline-empty');
  let selected = 'all';
  const update = () => {
    const term = (search?.value || '').trim().toLocaleLowerCase();
    let count = 0;
    for (const card of cards) {
      const categories = (card.dataset.category || '').split(' ');
      const matchesCategory = selected === 'all' || categories.includes(selected);
      const matchesText = !term || (card.dataset.search + ' ' + card.textContent).toLocaleLowerCase().includes(term);
      card.hidden = !(matchesCategory && matchesText);
      if (!card.hidden) count++;
    }
    for (const year of timeline.querySelectorAll('.timeline-year')) {
      year.hidden = !cards.some(card => !card.hidden && card.dataset.year === year.querySelector('span')?.textContent);
    }
    if (empty) empty.hidden = count !== 0;
  };
  for (const filter of filters) {
    filter.addEventListener('click', () => {
      selected = filter.dataset.timelineFilter;
      for (const button of filters) button.setAttribute('aria-pressed', String(button === filter));
      update();
    });
  }
  search?.addEventListener('input', update);
  update();
}
