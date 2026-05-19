# Task Checklist: Firebase Comment Sync Fix
- [x] Change 1 — openWatch: comment key → stable hash
- [x] Change 2 — submitComment: videoId/contentId fields → stable hash
- [x] Change 3 — submitComment: engagement call → pass content object
- [x] Change 4 — updateContentEngagementCounts: split cKey vs recordId

# Task Checklist: Comment Delete Feature
- [x] Change 1 — _buildCommentHTML: add parentId param + canDelete + deleteLabel
- [x] Change 2 — renderComments: pass c.id as parentId when rendering replies
- [x] Change 3 — New deleteComment() function with modal confirmation + Firebase delete

# Task Checklist: Profile Page – My Works + Thumbnails
- [x] Change 1 — helper functions (_profGetThumbnail, _profUserIdentities, _profCrewMemberMatchesUser, _profIsDirectorOfContent, _profIsCreatorOfContent, _profIsParticipantOfContent)
- [x] Change 2 — renderProfileSections: My Works uses _profIsCreatorOfContent; Participation deduplicates via worksSet
- [x] Change 3 — _profContentCard: real thumbnail using thumb r-film

# Task Checklist: Sidebar Genre Filter → Category Page
- [x] Change 1 — CSS: category page grid styles
- [x] Change 2 — HTML: #category-page container
- [x] Change 3 — JS: rewrite filterType
- [x] Change 4 — JS: new renderCategoryPage function

# Task Checklist: Pitch Campaigns Profile Section
- [x] Change 1 — HTML: pitch tab button + prof-sec-pitch section (between collab and reviews)
- [x] Change 2 — i18n: tab_pitch + prof_pitch_empty in RU/KZ/EN (both i18n blocks per lang)
- [x] Change 3 — switchProfTab: add pitch → prof-sec-pitch to secMap
- [x] Change 4 — renderProfileSections: pitch block clones .pitch-grid .pc nodes matching user

# Task Checklist: Mobile Performance — Extract Base64 Images
- [x] Change 1 — Extract dark topbar logo (12 KB) → aitu-logo-dark.png, replace inline base64 with ./aitu-logo-dark.png
- [x] Change 2 — Extract About hero logo (156 KB) → aitu-about-hero.png, replace inline base64 with ./aitu-about-hero.png
- [x] Change 3 — Extract light topbar logo (31 KB) → aitu-logo-light.png, update setTheme() to use relative URL
- [x] Result: HTML file reduced from 773 KB → 488 KB (−284 KB, −37%)

# Task Checklist: Mobile Loading Fix — Non-blocking Startup
- [x] Change 1 — restoreSession: theme+lang set FIRST from localStorage (no network wait)
- [x] Change 2 — restoreSession: renderUserContent() called immediately after theme/lang (empty state)
- [x] Change 3 — restoreSession: loadServerContent() NOT awaited — runs in background, calls renderUserContent() internally when data arrives
- [x] Change 4 — restoreSession: migrateLocalAyaDataToFirebase + loadUserByIdFromFirebase moved to .then() chain (fully background, parallel with content load)
- [x] Change 5 — applyLang: removed _hasContent guard — renderUserContent() always called unconditionally (matches original behavior)
- [x] Change 6 — loadServerContent: always calls renderUserContent() after Firebase responds (removed `if (added)` gate)
- [x] Result: Content renders as soon as Firebase responds (~1-3s), not after full sequential await chain (~20s on mobile)

# Task Checklist: Hash Routing
- [x] Change 1 — _routerPaused flag + _setHash() helper near BN_MAP
- [x] Change 2 — goPage(): call _setHash() at top (profile/{userId} or #{id})
- [x] Change 3 — applyRoute() function: parses hash, dispatches to goPage/openWatch/filterType
- [x] Change 4 — _restoreWatchRoute(): 20×500ms retry loop for #watch/{contentId}
- [x] Change 5 — openWatch(): call _setHash('#watch/' + content.id) at top
- [x] Change 6 — filterType(): call _setHash('#home' or '#category/{type}') at top
- [x] Change 7 — restoreSession: call applyRoute(location.hash) after loadServerContent()
- [x] Change 8 — window hashchange listener: calls applyRoute() if not _routerPaused

# Task Checklist: Home Carousel Restructure
- [x] Change 1 — HTML: 4 rows → 7 genre rows (festival removed, films/doc/social/short added)
- [x] Change 2 — ROW_MAP: each category → dedicated row
- [x] Change 3 — i18n EN: row_festival → row_films/row_doc/row_social/row_short
- [x] Change 4 — i18n RU: same replacements
- [x] Change 5 — i18n KZ: same replacements
- [x] Change 6 — renderUserContent: genre-row visibility pass after render
