const revealElements = document.querySelectorAll("[data-reveal]");

if ("IntersectionObserver" in window) {
  const observer = new IntersectionObserver(
    (entries, obs) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        obs.unobserve(entry.target);
      });
    },
    { threshold: 0.12 }
  );

  revealElements.forEach((el, idx) => {
    el.style.transitionDelay = `${idx * 70}ms`;
    observer.observe(el);
  });
} else {
  revealElements.forEach((el) => el.classList.add("is-visible"));
}
