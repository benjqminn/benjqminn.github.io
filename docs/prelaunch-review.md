# Portfolio review · October 28, 2026

**Editorial rating: 8.3/10.** This is a considered design/content assessment, not an automated accessibility or performance score. The local portfolio is credible enough for a focused launch after owner review and live deployment checks. Its strongest qualities are its identity, accurate positioning, and simple implementation. Its main weakness is the depth of publicly inspectable project evidence.

| Area | Rating | Assessment |
| --- | --- | --- |
| Visual identity | 8.7/10 | The woodland palette, large serif name, restrained landscape symbol, and consistent action controls form a recognizable identity. Real project screenshots and official badges give the page useful visual anchors. Small metadata still requires more attention than the main headings. |
| Personal presence | 8.0/10 | The owner's name, Charlotte context, campus work, short bodybuilding detail, and chosen quote add personality without inventing a lifestyle story. A real portrait or a concrete personal project decision would make it more recognizably his in a future revision. Neither is required for launch. |
| Professional positioning | 8.5/10 | Cloud, identity, detection, engineering, and emerging technology are represented. Dates and employer wording reflect the owner's corrections. The site presents the completed internship and incoming program clearly, while avoiding detailed employer operations in the page copy. |
| Technical evidence | 7.0/10 | Obscura has three actual interface screenshots and an accurately labeled private implementation. Credentials have direct issued-record links. AWS research and Trace still link to profile summaries; the site cannot yet substantiate their depth through a primary report, public code, or a detailed case study. |
| Usability and readability | 8.6/10 | Main actions are legible, navigation behaves consistently, and galleries work with keyboard and manual controls. Credential titles are readable separately from their badge artwork. The long single page is sensible for launch, but carousels make later items less immediately discoverable than the first visible row. |
| Engineering and maintenance | 8.8/10 | A small static artifact, no package dependencies, self-hosted assets, restrictive CSP, and a public-only build suit GitHub Pages. Actual hosted workflow behavior and live routes remain unverified until publication is approved. |

## Fit with the original plan and the owner

The redesign replaces outdated course navigation with a professional front door. It preserves the cinematic nature aesthetic the owner preferred and avoids the rejected initials monogram, exaggerated slogans, skill percentages, and separate bodybuilding section. Personal ambition appears in About Me and the subtle credited quote. There is no influence-name list in the biography.

The first credential row deliberately mixes AWS Solutions Architect, Security+, and CloudOps rather than presenting only cloud credentials. Selected work covers research, a security tool, and a team application. The focus-area icons describe interests rather than pretending to measure proficiency.

The M.S. date is December 2026, the B.S. is May 2026 with the cybersecurity concentration and no Mathematics minor, the SOC internship is completed in summer 2026, and the Technology Analyst Development Program is incoming in 2027. The downloadable résumé remains byte-for-byte the PDF the owner approved, including its original contact details and experience bullets.

## Findings addressed during review

- Replaced the old certification-repository shortcut with the complete 23-record Credly collection, verified Azure Fundamentals, ten additional course certificates, and the owner's Credly profile. Filters retain a manageable gallery while exposing Office, skills, training, and the expired candidacy separately.
- Added actual Obscura images and explanatory research/stack visuals. The dashboard is shown first; screenshots are not presented as detection benchmarks.
- Corrected the AWS research fragment to the actual GitHub heading permalink and linked Trace directly to its summary.
- Fixed the navigation indicator at the bottom of the page so Contact becomes current.
- Increased project body copy to 15 px and key metadata and dates to 12 px. Main text action labels remain at least 14 px.
- Made the full credential card a single accessible link, so selecting the badge image and its action reach the same verification record.

## Remaining concerns, in priority order

1. **Resolved after approval: the linked Obscura README promised recruiters a personal access token.** This was a public wording issue, not evidence that a token had leaked. Both promises and related token-access claims were replaced with guided source review or appropriate repository access in [commit d159183](https://github.com/benjqminn/obscura-project/commit/d159183116136399c7c18abf7a29014ca06febe7). Use GitHub's normal collaborator access when appropriate; [GitHub treats personal access tokens like passwords](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens).
2. **AWS research and Trace need primary evidence for a stronger technical impression.** A short case study covering the question, the owner's decisions, one concrete artifact, and limitations would help more than another visual redesign. Do not add the profile's research percentages until the underlying report is reviewed.
3. **Verify the deployed site after approval.** Successful local builds do not establish that GitHub's workflow, live HTTPS, résumé download, or retired course URLs behave correctly. Pages must publish the new `dist/` artifact through GitHub Actions.

The university email's long-term availability should be revisited when a replacement is chosen; LinkedIn already supplies a second contact path. A custom domain, portrait, additional case studies, and more animation can wait.

## Launch boundary

The owner initially chose “Keep the preview for edits,” then explicitly approved the reviewed portfolio's publication and the Obscura README cleanup on October 28, 2026. This review records the prelaunch assessment. A successful publishing workflow and live checks are still required before reporting the site as deployed.

Keep the remaining work to evidence/copy cleanup, owner review, and a verified launch. The November 13, 2026 AWS Community Day commitment takes priority over further portfolio expansion. This site should support that work, not consume the preparation window.
