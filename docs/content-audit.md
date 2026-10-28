# Source audit · October 28, 2026

Inspected the exact UNC Charlotte site at https://webpages.charlotte.edu/btayl106/ and downloaded its current counterpart, `benjqminn/benjqminn.github.io`, for local work. Both showed the old portfolio. No external account was modified by this audit.

## Retained and corrected

- Name, Charlotte location, email, LinkedIn, and GitHub from existing public profiles.
- M.S. Cybersecurity: **expected December 2026**, confirmed by the user and current GitHub profile.
- B.S. Computer Science: completed May 2026, confirmed by current profile and supplied résumé.
- The owner clarified that he did not earn a Mathematics minor. The new site lists only the B.S. and cybersecurity concentration, and the content check rejects the incorrect minor claim.
- Summer 2026 Wells Fargo SOC internship: completed; website copy stays general.
- Incoming 2027 Wells Fargo Technology Analyst Development Program: supplied directly by the user. No specific team, placement, or responsibilities are inferred.
- AWS forensic visibility research and Trace contributions: current public profile README. Link labels say summary, not full paper or public source code. Quantitative research results are omitted until the primary report is available for review.
- Obscura: current public project overview. Private implementation is labeled accurately.
- Campus involvement: current public profile and owner-supplied résumé.
- All 23 public Credly records: the owner's [public profile](https://www.credly.com/users/benjamin-taylor.d6c23975), inspected October 28, 2026. Official badge artwork is self-hosted and each card links to its individual issued record. This includes seven Microsoft Office credentials, four AWS demonstrated-skill badges, and three course certificates. The expired ISC2 Candidate record is explicitly labeled as expired former candidacy, not a current certification, and is available through the Archive filter.
- Azure Fundamentals: the owner's [Microsoft Learn verification record](https://learn.microsoft.com/api/credentials/share/en-us/BenjaminTaylor-3545/523E066CBD6D629F?sharingId=8A34160597610936) identifies Benjamin Taylor, earned January 27, 2026, active status. Its official Fundamentals badge is self-hosted from the artwork shown on that record.
- Claude Academy AI Fluency for builders: [direct completion verification](https://academy.claude.com/verify/3104a4a7ef780937d2fa06d99b95fb3d), issued to Ben on October 20, 2026, supplied by the owner and inspected publicly. The site calls it a course certificate and uses a native book illustration and issuer name, not a fabricated official badge.
- LinkedIn Learning Data Analytics: [direct public completion record](https://www.linkedin.com/learning/certificates/49de4fe4e44ca9d02f21f5c01007ccaff17b9bf76a0475873f5d58a43d9ad89b), Benjamin Taylor, completed March 15, 2025. The general profile certification listing required sign-in, but this individual record and its actual certificate image were public.
- Eight further saved course/learning-path certificates: three TryHackMe paths, four freeCodeCamp offerings (including Foundational C# with Microsoft), and Getting Started with RISC-V from LinkedIn Learning. The actual certificates were visually inspected in the existing portfolio or public certificate repository. Where the owner supplied direct completion URLs, those are used instead of generic profile links. Repeated Cisco and Google records are not duplicated.

The complete collection has 34 records: nine cloud/security certifications, seven Office certifications, four demonstrated-skill badges, thirteen course certificates, and one expired candidacy. Sources, dates, type labels, and local artwork are maintained in `credential-sources.json`; it is an authoring record and is not fetched by the live website.
- Current résumé: the exact Desktop PDF selected by the owner. Its unchanged public use, including phone number, employer tool names and investigation metrics, was explicitly selected after those details were highlighted.

## Removed from the published experience

Old course navigation and pages, skill-logo walls, autoplay certificate/research carousels, learning percentage bars, the May 2027 graduation date, outdated student narrative, and duplicate research captions.

The replacement uses a small set of meaningful interest icons, a three-step research workflow, a documented Trace stack diagram, three real Obscura screenshots, and a filterable manual credential gallery. These are explanatory visuals, not new claims of research outcomes or detection accuracy. Galleries have no autoplay; all their content remains available through native horizontal scrolling without JavaScript.

Historical course content is excluded by the new `public/`-only build, while preserving repository history. Legacy content remains accessible through the public repository itself. A Pages publishing-source change is needed to make the build exclusion effective on the live domain.

## Still worth confirming after launch

The owner later added that he is an aspiring bodybuilder. This is included briefly in About Me without invented competition history, training statistics, or a list of influences. The original short Arnold quote is retained as a subtle design element with attribution: [source quoting the autobiography](https://colossus.com/episode/senra-arnold-schwarzenegger-the-education-of-a-bodybuilder/).

Publication was initially held for preview edits. The owner subsequently approved publication and the Obscura README cleanup on October 28, 2026. The README cleanup is recorded in [commit d159183](https://github.com/benjqminn/obscura-project/commit/d159183116136399c7c18abf7a29014ca06febe7). The portfolio's deployment must be established separately by its workflow result and live URL checks.

Long-term email after university account retirement; primary research report for a future full case study; any public Trace repository the owner wants linked. The current school email is preserved because it is the supplied contact, with LinkedIn available as an alternative.
