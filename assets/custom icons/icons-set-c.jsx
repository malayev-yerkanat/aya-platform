// AYA Icons — Pitch + Collections + Feedback + Badges + Identity

const f = (style, stroke, sage) => {
  if (style === 'line') return { fill: 'none', accent: 'none' };
  if (style === 'filled') return { fill: stroke, accent: stroke };
  return { fill: 'none', accent: sage };
};

// ---------- PITCH / CROWDFUNDING ----------
const PITCH = {
  Funding: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="9" fill={style === 'filled' ? fill : 'none'} />
        <path d="M14.5 9 C13.5 8 9.5 8 9.5 11 C9.5 13.5 14.5 13 14.5 15 C14.5 17.5 10 17.5 9 16.5" stroke={style === 'filled' ? '#1A1F12' : stroke} fill="none" />
        <path d="M12 6 V18" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Goal: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="9" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="12" cy="12" r="5" fill={style === 'filled' ? '#1A1F12' : 'none'} />
        <circle cx="12" cy="12" r="1.6" fill={stroke} stroke="none" />
      </>
    );
  },
  Backers: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && (<>
          <circle cx="8" cy="9" r="3" fill={accent} stroke="none" />
          <circle cx="16" cy="9" r="3" fill={accent} stroke="none" />
        </>)}
        <circle cx="8" cy="9" r="3" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="16" cy="9" r="3" fill={style === 'filled' ? fill : 'none'} />
        <path d="M3 19 C3.5 16 5.5 14.5 8 14.5 C10.5 14.5 12.5 16 13 19" />
        <path d="M11 19 C11.5 16 13.5 14.5 16 14.5 C18.5 14.5 20.5 16 21 19" />
      </>
    );
  },
  Progress: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 18 L9 12 L13 16 L21 6 V18 Z" fill={accent} stroke="none" />}
        {style === 'filled' && <path d="M3 18 L9 12 L13 16 L21 6 V18 Z" fill={stroke} />}
        <path d="M3 18 L9 12 L13 16 L21 6" />
        <path d="M16 6 H21 V11" />
        <path d="M3 21 H21" />
      </>
    );
  },
  CampaignLive: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="4" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="4" fill={style === 'filled' ? fill : 'none'} />
        <path d="M5 5 C2 8 2 16 5 19" />
        <path d="M19 5 C22 8 22 16 19 19" />
        <path d="M8 8 C6 10 6 14 8 16" />
        <path d="M16 8 C18 10 18 14 16 16" />
      </>
    );
  },
  CampaignEnded: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="9" fill={style === 'filled' ? fill : 'none'} />
        <path d="M8 12 H16" stroke={style === 'filled' ? '#1A1F12' : stroke} strokeWidth={2.5} />
      </>
    );
  },
};

// ---------- COLLECTIONS ----------
const COLLECTIONS = {
  Folder: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 7 H10 L12 9 H21 V19 H3 Z" fill={accent} stroke="none" />}
        <path d="M3 7 H10 L12 9 H21 V19 H3 Z" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  AddCollection: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 7 H10 L12 9 H21 V19 H3 Z" fill={accent} stroke="none" />}
        <path d="M3 7 H10 L12 9 H21 V19 H3 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M12 12 V16 M10 14 H14" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  PublicCollection: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 7 H10 L12 9 H21 V19 H3 Z" fill={accent} stroke="none" />}
        <path d="M3 7 H10 L12 9 H21 V19 H3 Z" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="12" cy="14" r="3" stroke={style === 'filled' ? '#1A1F12' : stroke} fill="none" />
        <path d="M9 14 H15 M12 11 C13.5 12.5 13.5 15.5 12 17 M12 11 C10.5 12.5 10.5 15.5 12 17" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  PrivateCollection: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 7 H10 L12 9 H21 V19 H3 Z" fill={accent} stroke="none" />}
        <path d="M3 7 H10 L12 9 H21 V19 H3 Z" fill={style === 'filled' ? fill : 'none'} />
        <rect x="10" y="13" width="4" height="4" stroke={style === 'filled' ? '#1A1F12' : stroke} fill="none" />
        <path d="M11 13 V11.5 C11 10.7 11.5 10 12 10 C12.5 10 13 10.7 13 11.5 V13" stroke={style === 'filled' ? '#1A1F12' : stroke} fill="none" />
      </>
    );
  },
  Favorites: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 7 H10 L12 9 H21 V19 H3 Z" fill={accent} stroke="none" />}
        <path d="M3 7 H10 L12 9 H21 V19 H3 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M12 17 C9 15 8 13.5 8 12.5 C8 11.5 8.7 11 9.5 11 C10.3 11 11 11.5 12 12.5 C13 11.5 13.7 11 14.5 11 C15.3 11 16 11.5 16 12.5 C16 13.5 15 15 12 17 Z" stroke={style === 'filled' ? '#1A1F12' : stroke} fill={style === 'duotone' ? sage : 'none'} />
      </>
    );
  },
};

// ---------- FEEDBACK & SOCIAL ----------
const FEEDBACK = {
  Comment: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 5 H21 V17 H10 L6 21 V17 H3 Z" fill={accent} stroke="none" />}
        <path d="M3 5 H21 V17 H10 L6 21 V17 H3 Z" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  Reply: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M9 5 L3 11 L9 17 V13 H17 V19 H21 V11 H9 Z" fill={accent} stroke="none" />}
        {style === 'filled' && <path d="M9 5 L3 11 L9 17 V13 H17 V19 H21 V11 H9 Z" fill={stroke} />}
        <path d="M9 5 L3 11 L9 17" />
        <path d="M3 11 H17 V19" />
      </>
    );
  },
  Thread: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && (<>
          <rect x="3" y="4" width="14" height="9" rx="1" fill={accent} stroke="none" />
          <rect x="7" y="11" width="14" height="9" rx="1" fill={accent} stroke="none" />
        </>)}
        <rect x="3" y="4" width="14" height="9" rx="1" fill={style === 'filled' ? fill : 'none'} />
        <rect x="7" y="11" width="14" height="9" rx="1" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  Mention: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="9" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="12" cy="12" r="3" stroke={style === 'filled' ? '#1A1F12' : stroke} fill="none" />
        <path d="M15 9 V13.5 C15 14.5 16 15 16.5 15 C17.5 15 18 14 18 13 V12" stroke={style === 'filled' ? '#1A1F12' : stroke} fill="none" />
      </>
    );
  },
  Applause: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M6 11 V19 C6 20 7 21 8 21 H14 C16 21 17 19 17 17 V12 C17 11 16 11 16 12 V8 C16 7 15 7 15 8 V6 C15 5 14 5 14 6 V8 L11 4 C10 3 9 4 10 5 L13 11 Z" fill={accent} stroke="none" />}
        <path d="M6 11 V19 C6 20 7 21 8 21 H14 C16 21 17 19 17 17 V12 C17 11 16 11 16 12 V8 C16 7 15 7 15 8 V6 C15 5 14 5 14 6 V8 L11 4 C10 3 9 4 10 5 L13 11 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M3 6 L4.5 8 M19 4 L18 6 M21 9 L19 9.5" />
      </>
    );
  },
  Reaction: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="9" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="9" cy="10.5" r="0.8" fill={style === 'filled' ? '#1A1F12' : stroke} stroke="none" />
        <circle cx="15" cy="10.5" r="0.8" fill={style === 'filled' ? '#1A1F12' : stroke} stroke="none" />
        <path d="M8.5 14.5 C9.5 16 10.5 16.5 12 16.5 C13.5 16.5 14.5 16 15.5 14.5" stroke={style === 'filled' ? '#1A1F12' : stroke} fill="none" />
      </>
    );
  },
};

// ---------- BADGES & STATUS ----------
const BADGES = {
  FestivalWinner: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M6 4 H18 V11 C18 14 15 16 12 16 C9 16 6 14 6 11 Z" fill={accent} stroke="none" />}
        <path d="M6 4 H18 V11 C18 14 15 16 12 16 C9 16 6 14 6 11 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M6 6 H3 V8 C3 10 5 11 6 11" />
        <path d="M18 6 H21 V8 C21 10 19 11 18 11" />
        <path d="M9 16 V20 H15 V16" />
        <path d="M8 21 H16" />
      </>
    );
  },
  OfficialSelection: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M12 2 C9 4 5 4 3 4 C3 12 6 18 12 22 C18 18 21 12 21 4 C19 4 15 4 12 2 Z" fill={accent} stroke="none" />}
        <path d="M12 2 C9 4 5 4 3 4 C3 12 6 18 12 22 C18 18 21 12 21 4 C19 4 15 4 12 2 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M9 12 L11 14 L15 9" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  New: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M12 2 L14 8 L20 8 L21 14 L18 18 L20 22 L14 21 L12 22 L10 21 L4 22 L6 18 L3 14 L4 8 L10 8 Z" fill={accent} stroke="none" />}
        <path d="M12 2 L14 8 L20 8 L21 14 L18 18 L20 22 L14 21 L12 22 L10 21 L4 22 L6 18 L3 14 L4 8 L10 8 Z" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  Live: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="3.5" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="3.5" fill={style === 'filled' ? fill : 'none'} />
        <path d="M7 7 C5 9 5 15 7 17" />
        <path d="M17 7 C19 9 19 15 17 17" />
        <path d="M4 4 C1.5 7.5 1.5 16.5 4 20" />
        <path d="M20 4 C22.5 7.5 22.5 16.5 20 20" />
      </>
    );
  },
  Hot: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M12 21 C8 19.5 6 16.5 6 13 C6 9.5 8.5 7 10.5 5.5 C10.5 8.5 12.5 9.5 14 6 C16.5 8 18 10.5 18 13.5 C18 17 16 19.7 12 21 Z" fill={accent} stroke="none" />}
        <path d="M12 21 C8 19.5 6 16.5 6 13 C6 9.5 8.5 7 10.5 5.5 C10.5 8.5 12.5 9.5 14 6 C16.5 8 18 10.5 18 13.5 C18 17 16 19.7 12 21 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M12 17 C10.7 16.3 10 15.3 10 14 C10 12.8 10.8 11.8 12 11 C12.2 12.4 13.2 12.8 14 11.5 C14.8 12.4 15.2 13.3 15.2 14.4 C15.2 15.7 14.2 16.7 12 17 Z" fill={style === 'duotone' ? stroke : 'none'} stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Verified: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M12 2 L14.5 4 L18 4 L18 7.5 L20.5 9.5 L19 12 L20.5 14.5 L18 16.5 L18 20 L14.5 20 L12 22 L9.5 20 L6 20 L6 16.5 L3.5 14.5 L5 12 L3.5 9.5 L6 7.5 L6 4 L9.5 4 Z" fill={accent} stroke="none" />}
        <path d="M12 2 L14.5 4 L18 4 L18 7.5 L20.5 9.5 L19 12 L20.5 14.5 L18 16.5 L18 20 L14.5 20 L12 22 L9.5 20 L6 20 L6 16.5 L3.5 14.5 L5 12 L3.5 9.5 L6 7.5 L6 4 L9.5 4 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M9 12 L11 14 L15 10" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Debut: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="9" fill={style === 'filled' ? fill : 'none'} />
        <path d="M12 7 V12 L12 7 M9 9 L12 12 L15 9" stroke={style === 'filled' ? '#1A1F12' : stroke} fill="none" />
        <path d="M12 7 L9 12 H15 Z" stroke={style === 'filled' ? '#1A1F12' : stroke} fill={style === 'duotone' ? stroke : 'none'} />
        <path d="M8 16 H16" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
};

// ---------- PLATFORM IDENTITY ----------
const IDENTITY = {
  Logomark: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    // A·Y·A — three triangular peaks (A's), middle one inverted (Y's center stroke)
    // Reads as a tight monogram with editorial confidence
    const left = "M2 20 L6 5 L10 20 Z";
    const right = "M14 20 L18 5 L22 20 Z";
    const mid = "M9 5 L12 12 L15 5 M12 12 V20";
    return (
      <>
        {style === 'duotone' && (<>
          <path d={left} fill={accent} stroke="none" />
          <path d={right} fill={accent} stroke="none" />
        </>)}
        {style === 'filled' && (<>
          <path d={left} fill={fill} />
          <path d={right} fill={fill} />
          <path d="M9 5 L12 12 L15 5 L13.5 5 L12 8.5 L10.5 5 Z" fill={fill} stroke="none" />
          <path d="M11.2 12 H12.8 V20 H11.2 Z" fill={fill} stroke="none" />
        </>)}
        <path d={left} fill="none" />
        <path d={right} fill="none" />
        <path d={mid} fill="none" />
        {/* crossbars on the A's */}
        <path d="M3.7 16 H8.3" />
        <path d="M15.7 16 H20.3" />
      </>
    );
  },
  KazakhOrnament: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    // Qoshqar müiz — bold mirrored ram-horn spirals filling the frame
    const leftHorn = "M12 12 C12 6 9 3 5 3 C2 3 1 6 3 8 C5 10 8 9 8 6";
    const rightHorn = "M12 12 C12 6 15 3 19 3 C22 3 23 6 21 8 C19 10 16 9 16 6";
    const diamond = "M12 12 L17 16.5 L12 21 L7 16.5 Z";
    return (
      <>
        {style === 'duotone' && (<>
          <path d={leftHorn} fill={accent} stroke="none" />
          <path d={rightHorn} fill={accent} stroke="none" />
          <path d={diamond} fill={accent} stroke="none" />
        </>)}
        {style === 'filled' && (<>
          <path d={leftHorn} fill={fill} />
          <path d={rightHorn} fill={fill} />
          <path d={diamond} fill={fill} />
        </>)}
        <path d={leftHorn} fill="none" />
        <path d={rightHorn} fill="none" />
        <path d={diamond} fill="none" />
      </>
    );
  },
  FilmGrain: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    // Filmstrip with sprocket holes + grain dots inside
    // Filled = filmstrip silhouette with holes punched out (cream shows thru)
    const dotColor = style === 'filled' ? '#1A1F12' : (style === 'duotone' ? stroke : stroke);
    return (
      <>
        {style === 'duotone' && <rect x="4" y="3" width="16" height="18" rx="1" fill={accent} stroke="none" />}
        {style === 'filled' && <rect x="4" y="3" width="16" height="18" rx="1" fill={fill} />}
        <rect x="4" y="3" width="16" height="18" rx="1" fill="none" />
        {/* sprocket holes — left & right strips */}
        {[5.5, 9, 12.5, 16, 19.5].map((cy, i) => (
          <React.Fragment key={i}>
            <rect x="5.5" y={cy - 1} width="2" height="2" rx="0.4"
              fill={style === 'filled' ? '#1A1F12' : 'none'} stroke={stroke} />
            <rect x="16.5" y={cy - 1} width="2" height="2" rx="0.4"
              fill={style === 'filled' ? '#1A1F12' : 'none'} stroke={stroke} />
          </React.Fragment>
        ))}
        {/* grain specks centered */}
        <circle cx="11" cy="7" r="0.6" fill={dotColor} stroke="none" />
        <circle cx="13" cy="10" r="0.5" fill={dotColor} stroke="none" />
        <circle cx="10.5" cy="13" r="0.5" fill={dotColor} stroke="none" />
        <circle cx="13.5" cy="16" r="0.6" fill={dotColor} stroke="none" />
        <circle cx="11.5" cy="18" r="0.4" fill={dotColor} stroke="none" />
      </>
    );
  },
};

window.AYA_ICONS_C = { PITCH, COLLECTIONS, FEEDBACK, BADGES, IDENTITY };
