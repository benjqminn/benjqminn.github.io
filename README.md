# Benjamin Taylor · Portfolio

Static cybersecurity portfolio for https://benjqminn.github.io/.

## Edit and preview

Requires Node.js 22 or newer. There are no runtime or build dependencies to install.

```text
npm run dev
npm run check
npm run build
```

Preview: http://127.0.0.1:4173. Edit `public/index.html`, `public/site.css`, or `public/site.js`. Replace `public/assets/Benjamin-Taylor-Resume.pdf` to update the public résumé. The supplied résumé is intentionally unchanged, including its contact information and experience bullets, as approved by its owner.

Credential content is maintained in `docs/credential-sources.json`. After editing a record and adding its self-hosted artwork, run `npm run credentials` to regenerate the static credential region in the homepage, then run the normal checks and build. The renderer has no package dependencies and performs no network requests. Preserve direct issued-record links and distinguish certification exams, demonstrated skills, course completions, and expired memberships.

## Publish to the existing GitHub Pages site

The owner approved the finished preview and first publication on October 28, 2026. The following steps describe the publishing process; a successful workflow and checks of the live URLs are required to establish a completed deployment.

1. Review the local site and PDF. Review the complete changes before pushing.
2. Commit the reviewed files to the existing `benjqminn/benjqminn.github.io` repository on `main`.
3. In the repository's Settings → Pages → Build and deployment, set Source to **GitHub Actions**. Keep Enforce HTTPS enabled.
4. Run the `Publish portfolio` workflow if it has not already started. Its deploy job needs the existing `github-pages` environment to allow `main`.
5. Confirm the workflow finishes successfully, then verify the actual HTTPS homepage, résumé download, mobile navigation, and custom 404. Check that `/itis3135/` returns 404.
6. Only after verification, update the GitHub profile's website link and other professional profiles away from UNC Charlotte hosting.

The workflow publishes **only `dist/`, copied from `public/`**. Historical course directories, old documents, screenshots, and the previous root website remain in source control but are excluded from the deployed site. They will still be viewable in the public repository and Git history. Removing those from public repository history is a separate action, not part of this site migration.

If the branch publishing setting remains at `main / (root)`, the old site will continue to publish. Switching to GitHub Actions is essential for the coursework exclusion. Do not simply upload the whole repository as a Pages artifact.

## Hosting and cost

GitHub Pages is available for public repositories on GitHub Free. This site uses a standard public GitHub runner, no paid services, no AWS resources, and no third-party form service. The existing `github.io` address needs no domain purchase or DNS change. A custom domain can be added later in Settings → Pages; configure and verify ownership using GitHub's current instructions before changing DNS. HTTPS is supported on GitHub's default domain and on correctly configured custom domains.

- [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages)
- [Custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
- [HTTPS](https://docs.github.com/en/pages/getting-started-with-github-pages/securing-your-github-pages-site-with-https)
- [Custom domains](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site)

## Privacy, security, and accessibility

All web assets are self-hosted. No analytics, cookies, external fonts, forms, API calls, or client-side credentials are used. Contact uses `mailto:`. The homepage's CSP is restrictive and delivered through a meta tag; GitHub Pages does not offer arbitrary response headers, so protections such as CSP `frame-ancestors` cannot be set here. The local server's `nosniff` header is a local development setting, not a claim about live Pages headers.

The site uses semantic sections, a skip link, visible keyboard focus, a mobile menu with expanded state and Escape handling, reduced-motion support, and readable content without JavaScript. Automated checks supplement manual browser review; they are not a claim of formal WCAG certification.

Credential badges, certificate previews, and actual project screenshots are self-hosted. Their galleries support arrow controls, keyboard navigation, and native horizontal scrolling, with no autoplay or external API dependency. Credential filters expose the full collection by type without removing the content from the HTML. Badge provenance and direct verification records are documented in `docs/credential-sources.json`.

## Launch scope

Selected work, about, experience, education/certification links, contact, the approved PDF, and a useful 404 are the minimum launch. More case studies and a custom domain can follow after launch. Keep the November 13, 2026 AWS Community Day commitment ahead of optional portfolio expansion.
