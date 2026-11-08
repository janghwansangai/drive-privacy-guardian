// Intro video: a local poster first; YouTube (no-cookie) loads only when the visitor presses
// play — opening the page sends nothing to YouTube.
for (const box of document.querySelectorAll(".video[data-yt]")) {
  const id = box.dataset.yt;
  if (!/^[\w-]{11}$/.test(id)) continue;
  box.querySelector("button").addEventListener("click", () => {
    const f = document.createElement("iframe");
    f.src = `https://www.youtube-nocookie.com/embed/${id}?autoplay=1&rel=0`;
    f.title = "개인정보 보안관 소개·설치·사용법 영상";
    f.allow = "autoplay; encrypted-media; picture-in-picture; fullscreen";
    f.allowFullscreen = true;
    f.referrerPolicy = "strict-origin-when-cross-origin"; // YouTube needs the page origin to play
    box.replaceChildren(f);
  });
}
