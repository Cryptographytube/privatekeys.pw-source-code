UPLOAD INSTRUCTIONS
===================

This folder is a ready-to-host static copy of the website. Every page works
without any special server (no Python needed).

--- cPanel (Apache) ---
1. Open cPanel -> File Manager -> public_html
2. Upload EVERYTHING inside this "cpanel" folder into public_html
   (the files/folders, not the "cpanel" folder itself).
   Tip: zip this folder, upload the zip, then "Extract" in File Manager.
3. Make sure ".htaccess" was uploaded too (enable "Show Hidden Files" in
   File Manager settings if you don't see it).
4. Visit your domain. Pages like /keys/bitcoin/1, /brainwallet/bitcoin/2 and
   /puzzles/page/2 will work.

--- GitHub Pages ---
1. Create a repo and push EVERYTHING inside the "githubsource" folder to it.
2. Repo Settings -> Pages -> Build from branch -> main / root.
3. IMPORTANT: use a user site (username.github.io) OR a custom domain.
   Do NOT use a project URL like username.github.io/repo-name/ -- the links
   are root-absolute (/assets, /keys, ...) and would break on a sub-path.
   For a custom domain: Settings -> Pages -> add your domain (creates CNAME).

Note: the live "community scanner" stats need a backend and stay empty offline.
Everything else -- key generation, address derivation, balance lookups via
public blockchain APIs, all pages -- works.
