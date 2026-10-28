# Validation · October 28, 2026

Status: revised local version verified. The owner approved publication on October 28, 2026 after reviewing the preview. This document records checks performed before deployment; it does not by itself establish the status of the live site.

- `npm run check` passes for the homepage and 404, local file references, section anchors, unique IDs, restrictive page CSP, corrected career dates, general employer copy, valid résumé PDF, and a 1.5 MB total asset limit.
- `npm run build` passes. Its 47 output files include the two HTML pages, CSS, JavaScript, robots and sitemap files, `.nojekyll`, favicon, two responsive landscape images, three actual Obscura screenshots, 24 official badge images, nine completion-certificate previews, and approved PDF. No course directories, old root pages, source notes, original documents, or authoring registry are in the artifact.
- Total uncompressed artifact: approximately 1,350 KiB, including the approved PDF, both landscape variants, all project screenshots, and the entire credential artwork collection. This remains within the 1.5 MB source-asset budget. No Lighthouse score or real-user performance measurement is claimed.
- SHA-256 comparison confirms that the built résumé is byte-for-byte identical to the Desktop file selected by the owner. Its single rendered page was visually inspected.
- The revised local page was visually reviewed at a 1280-pixel desktop test viewport, and the complete page was inspected in a full-page screenshot. Both the landscape and real project screenshot loaded. Temporary viewport overrides were reset afterward.
- Browser layout checks at 320, 390, 768, and 1440 CSS pixels found no horizontal page overflow. Mobile navigation opens, exposes its expanded state, closes with Escape, and returns focus to its button.
- Keyboard activation of Skip to content focuses `main` after a small focusability fix.
- Copy email reports success in its live status region.
- The retired `/itis3135/` route shows the custom not-found page in the local public-only server; its return link opens the new homepage.
- No browser console warnings or errors were captured on the tested homepage.
- Reduced motion and forced-color rules are present. The content and links are in the HTML; the navigation remains available without script enhancement. These are code checks, not a formal assistive-technology audit or WCAG conformance certification.

Before declaring launch complete, confirm the GitHub workflow succeeded, the live HTTPS homepage is the new version, the live PDF matches the approved one, and old coursework URLs return an actual 404 on the public domain. GitHub Pages' publishing source must be GitHub Actions for the source/build separation to take effect.

The final visual revision restores the dark woodland palette and large serif name, replaces generic slogans with the owner's identity, and uses the actual Obscura alert-feed screenshot instead of a decorative research diagram. Bodybuilding is a brief detail within About Me. There is no list of personal influences or separate bodybuilding section. The short quote retained from the earlier site is credited and linked to a source.

## Visual reinforcement and manual galleries

- The owner's public Credly profile was inspected directly. All 23 records and their official image URLs are archived in `credential-sources.json`; the expired ISC2 Candidate record is now included with explicit expired-candidacy labeling. Azure's active Microsoft Learn record, Claude Academy's completion record, and the public LinkedIn Learning Data Analytics certificate were also inspected. Eight saved certificates were visually checked. The gallery has 34 records in total.
- The credential gallery shows three cards on desktop, two at intermediate widths, and one on a phone. All six filters were checked against their actual counts: All 34, Certifications 9, Skill badges 4, Microsoft Office 7, Courses 13, and Archive 1. Filter buttons expose their pressed state; filtering removes excluded cards from navigation and restarts the gallery at its first card.
- Desktop End reached `32–34 / 34` and disabled Next. Switching from that last page to Courses via keyboard activation reset the horizontal scroll to zero and showed the first course. On a 390 px phone viewport, the Office gallery reached `7 / 7` and disabled Next; the expired candidacy remained hidden in that category.
- Each entire credential card is one link with a distinct accessible name and direct issued-record URL. It has no nested links or duplicate tab stops.
- The project gallery contains three original development screenshots with descriptive captions and full-image links. Keyboard and control navigation, first/last bounds, and the single-image phone layout were manually checked.
- Gallery controls have 48 px targets, live page counts, and descriptive accessible names. There is no autoplay. Native horizontal scrolling and all HTML links remain available without enhancement. Reduced-motion rules disable smooth gallery scrolling.
- The interest strip, research workflow, and Trace stack diagram were reviewed in the rendered page. They describe documented interests/work rather than claiming new measured outcomes.
- Browser checks after the full-collection additions at 320, 390, 640, 768, 900, 1024, and 1440 CSS pixels found no horizontal document overflow. Filter labels remain 14 px with minimum 46 px target heights at every tested width. This does not replace physical touch-device testing.
- The AWS research and Trace links now use the observed GitHub heading permalinks. The Contact navigation indicator activates at the document bottom.

## Header and navigation polish

- Removed the `bt.` monogram from the header and favicon. The header now uses the owner's name; the favicon is a simple landscape mark.
- Removed the inaccurate Mathematics minor after the owner's correction. The content check guards against its return.
- Mobile navigation is an animated floating panel under a sticky header, rather than a block that pushes the page down. With the new nameplate at a 390 px viewport, opening it preserves the measured header height and hero position (both 86.67 px).
- Escape closes the panel, returns focus to its button, and makes the closed links inert. Pointer clicks outside the header and keyboard focus leaving the header dismiss it too.
- Selecting Experience closes the panel, updates the URL to `#experience`, and moves focus to `experience-heading`. Native link behavior remains intact on desktop and for modified clicks.
- Resizing to desktop clears mobile-only inert and hidden states. The larger header switches to the mobile menu at 900 px; no horizontal overflow or header collisions were found at 320, 390, 752, 900, 901, 1024, or 1440 px.
- At a 320 × 280 viewport, the panel ends at 268 px and scrolls internally, keeping all five links reachable. Reduced-motion CSS removes the navigation and button transitions.
- No warnings or errors were captured in the browser console during this verification. The Node syntax check, content check, and public-only build pass.

## Identity and action legibility

- The header now combines a native SVG landscape symbol, a serif nameplate, a readable professional descriptor, active section navigation, and a direct résumé action. The rejected initials monogram remains removed.
- Shared button styles use solid backgrounds, stronger borders, 14 px main labels, consistent padding, and distinct hover, pressed, and keyboard focus states. PDF accessory labels are 11 px.
- Computed normal-state checks of 19 visible desktop actions found a minimum main-label size of 14 px, a minimum hit-target height of 44 px, and a minimum text contrast ratio of 10.52:1. Primary and secondary action buttons are 48 px high or taller.
- Mobile menu links use 17 px labels and 56 px targets; its résumé action uses a 15 px label and the same target height. Escape and Tab dismissal still work, and selecting Work focuses `work-heading`.
- The current-section indicator followed navigation to Experience. Header and hero actions remain separated from the quote at all tested widths, with at least 40 px between the hero action group and the lower hero content.
- A tighter wordmark adjustment below 360 px prevents a second header row at 320 px without shrinking action labels. This was rechecked after the layout fix.
