let activeElement = null;

window.addEventListener("DOMContentLoaded", () => {
  const post = document.querySelector(".post");
  const toc = document.querySelector("nav[id='TableOfContents']");

  if (!post || !toc) {
    return;
  }

  const observer = new IntersectionObserver((entries) => {
    const contents = document.getElementById("contents");
    if (contents) {
      contents.innerHTML = "Contents";
    }

    entries.forEach((entry) => {
      if (activeElement) {
        document.querySelectorAll("nav[id='TableOfContents'] li").forEach((node) => {
          node.classList.add("inactive");
          node.classList.replace("active", "inactive");
        });
      }

      if (entry.intersectionRatio > 0) {
        activeElement = entry.target.getAttribute("id");
      }

      if (activeElement) {
        const activeLink = document.querySelector(
          `nav[id='TableOfContents'] li a[href="#${CSS.escape(activeElement)}"]`
        );

        if (activeLink && activeLink.parentElement) {
          activeLink.parentElement.classList.replace("inactive", "active");
        }
      }
    });
  });

  post.querySelectorAll("h1[id], h2[id], h3[id], h4[id], h5[id], h6[id]").forEach((section) => {
    observer.observe(section);
  });
});
