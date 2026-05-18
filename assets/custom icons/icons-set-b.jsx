// AYA Icons — Actions + Crew & People + User Roles + Content Metadata

const f = (style, stroke, sage) => {
  if (style === 'line') return { fill: 'none', accent: 'none' };
  if (style === 'filled') return { fill: stroke, accent: stroke };
  return { fill: 'none', accent: sage };
};

// ---------- ACTIONS ----------
const ACTIONS = {
  Bookmark: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M6 3.5 H18 V20.5 L12 16 L6 20.5 Z" fill={accent} stroke="none" />}
        <path d="M6 3.5 H18 V20.5 L12 16 L6 20.5 Z" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  Like: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M12 20 C5 15.5 3 12 3 8.5 C3 6 5 4 7.5 4 C9.5 4 11 5 12 6.5 C13 5 14.5 4 16.5 4 C19 4 21 6 21 8.5 C21 12 19 15.5 12 20 Z" fill={accent} stroke="none" />}
        <path d="M12 20 C5 15.5 3 12 3 8.5 C3 6 5 4 7.5 4 C9.5 4 11 5 12 6.5 C13 5 14.5 4 16.5 4 C19 4 21 6 21 8.5 C21 12 19 15.5 12 20 Z" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  Share: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && (<>
          <circle cx="6" cy="12" r="2.5" fill={accent} stroke="none" />
          <circle cx="18" cy="5" r="2.5" fill={accent} stroke="none" />
          <circle cx="18" cy="19" r="2.5" fill={accent} stroke="none" />
        </>)}
        <circle cx="6" cy="12" r="2.5" fill={style === 'filled' ? stroke : 'none'} />
        <circle cx="18" cy="5" r="2.5" fill={style === 'filled' ? stroke : 'none'} />
        <circle cx="18" cy="19" r="2.5" fill={style === 'filled' ? stroke : 'none'} />
        <path d="M8 11 L16 6.5 M8 13 L16 17.5" />
      </>
    );
  },
  Delete: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M5 7 H19 L17.5 20 H6.5 Z" fill={accent} stroke="none" />}
        <path d="M5 7 H19 L17.5 20 H6.5 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M3 7 H21" />
        <path d="M9 4 H15 V7" />
        <path d="M10 11 V16 M14 11 V16" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Report: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M5 4 H17 L14 8.5 L17 13 H5 Z" fill={accent} stroke="none" />}
        <path d="M5 4 H17 L14 8.5 L17 13 H5 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M5 4 V21" />
      </>
    );
  },
  Dots: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    const fillColor = style === 'duotone' ? accent : stroke;
    return (
      <>
        <circle cx="12" cy="5" r="1.6" fill={fillColor} stroke="none" />
        <circle cx="12" cy="12" r="1.6" fill={fillColor} stroke="none" />
        <circle cx="12" cy="19" r="1.6" fill={fillColor} stroke="none" />
        {style !== 'line' && (<>
          <circle cx="12" cy="5" r="1.6" />
          <circle cx="12" cy="12" r="1.6" />
          <circle cx="12" cy="19" r="1.6" />
        </>)}
      </>
    );
  },
  Plus: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" opacity="0.85" />}
        {style === 'filled' && <circle cx="12" cy="12" r="9" fill={stroke} />}
        {style !== 'line' && (
          <path d="M12 7 V17 M7 12 H17" stroke={style === 'filled' ? '#1A1F12' : stroke} />
        )}
        {style === 'line' && (
          <path d="M12 4 V20 M4 12 H20" />
        )}
      </>
    );
  },
  Edit: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M14.5 4.5 L19.5 9.5 L9 20 H4 V15 Z" fill={accent} stroke="none" />}
        <path d="M14.5 4.5 L19.5 9.5 L9 20 H4 V15 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M13 6 L18 11" />
      </>
    );
  },
  Filter: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 5 H21 L14 13 V20 L10 18 V13 Z" fill={accent} stroke="none" />}
        <path d="M3 5 H21 L14 13 V20 L10 18 V13 Z" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  Sort: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && (<>
          <path d="M7 4 V18 L4 15 M7 4 L10 7" fill={accent} stroke="none" />
          <path d="M17 20 V6 L20 9 M17 20 L14 17" fill={accent} stroke="none" />
        </>)}
        <path d="M7 4 V20" />
        <path d="M4 17 L7 20 L10 17" />
        <path d="M17 20 V4" />
        <path d="M14 7 L17 4 L20 7" />
      </>
    );
  },
  ArrowRight: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M4 11 H16 V7 L21 12 L16 17 V13 H4 Z" fill={accent} stroke="none" />}
        {style === 'filled' && <path d="M4 11 H16 V7 L21 12 L16 17 V13 H4 Z" fill={stroke} />}
        <path d="M4 12 H20" />
        <path d="M15 7 L20 12 L15 17" />
      </>
    );
  },
  Close: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" opacity="0.55" />}
        {style === 'filled' && <circle cx="12" cy="12" r="9" fill={stroke} />}
        <path d="M8 8 L16 16" stroke={style === 'filled' ? '#1A1F12' : stroke} />
        <path d="M16 8 L8 16" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Check: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" opacity="0.55" />}
        {style === 'filled' && <circle cx="12" cy="12" r="9" fill={stroke} />}
        <path d="M7 12.5 L10.5 16 L17 8" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Error: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M12 3 L21 20 H3 Z" fill={accent} stroke="none" opacity="0.55" />}
        <path d="M12 3 L21 20 H3 Z" fill={style === 'filled' ? stroke : 'none'} />
        <path d="M12 8 V13" stroke={style === 'filled' ? '#1A1F12' : stroke} />
        <circle cx="12" cy="16.5" r="0.8" fill={style === 'filled' ? '#1A1F12' : stroke} stroke="none" />
      </>
    );
  },
  Ban: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="9" fill={style === 'filled' ? fill : 'none'} />
        <path d="M6 18 L18 6" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Clipboard: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M6 5 H18 V21 H6 Z" fill={accent} stroke="none" />}
        <path d="M6 5 H18 V21 H6 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M9 5 C9.2 3.7 10.2 3 12 3 C13.8 3 14.8 3.7 15 5 V7 H9 Z" fill={style === 'filled' ? '#1A1F12' : 'none'} />
        <path d="M9 12 H15 M9 16 H14" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  ThemeDark: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M15.5 3.5 C12 4.5 9.5 7.5 9.5 11.5 C9.5 15.5 12.5 18.5 16.5 18.5 C17.7 18.5 18.8 18.2 19.8 17.6 C18.4 20 15.8 21.5 12.8 21.5 C8.2 21.5 4.5 17.8 4.5 13.2 C4.5 8.8 7.7 5.1 12 4.5 C13.1 4.3 14.3 4 15.5 3.5 Z" fill={accent} stroke="none" />}
        <path d="M15.5 3.5 C12 4.5 9.5 7.5 9.5 11.5 C9.5 15.5 12.5 18.5 16.5 18.5 C17.7 18.5 18.8 18.2 19.8 17.6 C18.4 20 15.8 21.5 12.8 21.5 C8.2 21.5 4.5 17.8 4.5 13.2 C4.5 8.8 7.7 5.1 12 4.5 C13.1 4.3 14.3 4 15.5 3.5 Z" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  ThemeLight: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="4" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="4" fill={style === 'filled' ? stroke : 'none'} />
        <path d="M12 2.5 V5 M12 19 V21.5 M2.5 12 H5 M19 12 H21.5" />
        <path d="M5.3 5.3 L7.1 7.1 M16.9 16.9 L18.7 18.7 M18.7 5.3 L16.9 7.1 M7.1 16.9 L5.3 18.7" />
      </>
    );
  },
};

// ---------- CREW & PEOPLE ----------
const CREW = {
  Director: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 9 L21 5 L21 12 L3 12 Z" fill={accent} stroke="none" />}
        <path d="M3 9 L21 5 L21 12 L3 12 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M3 12 H21 V20 H3 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M8 9 L11 12 M14 8 L17 12" />
      </>
    );
  },
  Producer: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <rect x="4" y="6" width="16" height="13" rx="1" fill={accent} stroke="none" />}
        <rect x="4" y="6" width="16" height="13" rx="1" fill={style === 'filled' ? fill : 'none'} />
        <path d="M9 6 V4 H15 V6" />
        <path d="M9 12 H15 M12 9 V15" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Cinematographer: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <rect x="3" y="7" width="13" height="11" rx="1" fill={accent} stroke="none" />}
        <rect x="3" y="7" width="13" height="11" rx="1" fill={style === 'filled' ? fill : 'none'} />
        <path d="M16 11 L21 8 V17 L16 14 Z" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="9.5" cy="12.5" r="2" />
      </>
    );
  },
  Editor: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && (<>
          <circle cx="6" cy="7" r="2.5" fill={accent} stroke="none" />
          <circle cx="6" cy="17" r="2.5" fill={accent} stroke="none" />
        </>)}
        <circle cx="6" cy="7" r="2.5" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="6" cy="17" r="2.5" fill={style === 'filled' ? fill : 'none'} />
        <path d="M8 8.5 L20 15.5" />
        <path d="M8 15.5 L20 8.5" />
      </>
    );
  },
  SoundDesigner: ({ style, stroke, sage }) => {
    const { accent } = f(style, stroke, sage);
    const c = style === 'filled' ? stroke : (style === 'duotone' ? accent : 'none');
    return (
      <>
        <path d="M3 12 V12 M6.5 9 V15 M10 5 V19 M13.5 7 V17 M17 10 V14 M20.5 12 V12" />
        {style === 'duotone' && (<>
          <rect x="2" y="11" width="20" height="2" fill={accent} stroke="none" opacity="0.4" />
        </>)}
        {style === 'filled' && (<>
          <rect x="5.5" y="9" width="2" height="6" fill={c} stroke="none" />
          <rect x="9" y="5" width="2" height="14" fill={c} stroke="none" />
          <rect x="12.5" y="7" width="2" height="10" fill={c} stroke="none" />
          <rect x="16" y="10" width="2" height="4" fill={c} stroke="none" />
        </>)}
      </>
    );
  },
  Screenwriter: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M5 3 H15 L19 7 V21 H5 Z" fill={accent} stroke="none" />}
        <path d="M5 3 H15 L19 7 V21 H5 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M15 3 V7 H19" />
        <path d="M8 11 H16 M8 14 H16 M8 17 H13" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Actor: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {/* Theatre masks */}
        {style === 'duotone' && (<>
          <path d="M3 5 C3 11 5 14 8 14 C11 14 13 11 13 5 Z" fill={accent} stroke="none" />
          <path d="M11 10 C11 16 13 19 16 19 C19 19 21 16 21 10 Z" fill={accent} stroke="none" />
        </>)}
        <path d="M3 5 C3 11 5 14 8 14 C11 14 13 11 13 5 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M11 10 C11 16 13 19 16 19 C19 19 21 16 21 10 Z" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  CrewGroup: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && (<>
          <circle cx="8" cy="8" r="3" fill={accent} stroke="none" />
          <circle cx="16" cy="9" r="2.5" fill={accent} stroke="none" />
        </>)}
        <circle cx="8" cy="8" r="3" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="16" cy="9" r="2.5" fill={style === 'filled' ? fill : 'none'} />
        <path d="M2.5 19 C3 15.5 5 13.5 8 13.5 C11 13.5 13 15.5 13.5 19" fill={style === 'filled' ? fill : 'none'} />
        <path d="M14 14 C16.5 14 19 15.5 21 18" />
      </>
    );
  },
};

// ---------- USER ROLES ----------
const ROLES = {
  Viewer: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M2 12 C5 6 8.5 4 12 4 C15.5 4 19 6 22 12 C19 18 15.5 20 12 20 C8.5 20 5 18 2 12 Z" fill={accent} stroke="none" />}
        <path d="M2 12 C5 6 8.5 4 12 4 C15.5 4 19 6 22 12 C19 18 15.5 20 12 20 C8.5 20 5 18 2 12 Z" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="12" cy="12" r="3" fill={style === 'filled' ? '#1A1F12' : 'none'} />
      </>
    );
  },
  Creator: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    // Person with a clapper-board head — director/creator of work
    return (
      <>
        {style === 'duotone' && <rect x="5" y="3" width="14" height="8" fill={accent} stroke="none" />}
        <rect x="5" y="3" width="14" height="8" fill={style === 'filled' ? fill : 'none'} />
        <path d="M5 6 L9 3 M11 6 L15 3 M17 6 L19 3.5" stroke={style === 'filled' ? '#1A1F12' : stroke} />
        <path d="M4 20 C4.5 16 7.5 13.5 12 13.5 C16.5 13.5 19.5 16 20 20" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  Studio: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 20 V9 L12 4 L21 9 V20 Z" fill={accent} stroke="none" />}
        <path d="M3 20 V9 L12 4 L21 9 V20 Z" fill={style === 'filled' ? fill : 'none'} />
        <rect x="9" y="13" width="6" height="7" fill={style === 'filled' ? '#1A1F12' : 'none'} />
        <path d="M3 20 H21" />
      </>
    );
  },
  Moderator: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M12 3 L20 6 V12 C20 16.5 16.5 19.5 12 21 C7.5 19.5 4 16.5 4 12 V6 Z" fill={accent} stroke="none" />}
        <path d="M12 3 L20 6 V12 C20 16.5 16.5 19.5 12 21 C7.5 19.5 4 16.5 4 12 V6 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M9 12 L11 14 L15 10" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Admin: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M14 2 L4 14 H11 L10 22 L20 10 H13 Z" fill={accent} stroke="none" />}
        <path d="M14 2 L4 14 H11 L10 22 L20 10 H13 Z" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
};

// ---------- CONTENT METADATA ----------
const META = {
  Tag: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 3 H12 L21 12 L12 21 L3 12 Z" fill={accent} stroke="none" />}
        <path d="M3 3 H12 L21 12 L12 21 L3 12 Z" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="7.5" cy="7.5" r="1.3" fill={style === 'filled' ? '#1A1F12' : stroke} stroke="none" />
      </>
    );
  },
  Year: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <rect x="3" y="5" width="18" height="16" rx="1" fill={accent} stroke="none" />}
        <rect x="3" y="5" width="18" height="16" rx="1" fill={style === 'filled' ? fill : 'none'} />
        <path d="M3 10 H21" />
        <path d="M8 3 V7 M16 3 V7" />
      </>
    );
  },
  Duration: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="9" fill={style === 'filled' ? fill : 'none'} />
        <path d="M12 7 V12 L15.5 14" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  Views: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M2 12 C5 7 8.5 5 12 5 C15.5 5 19 7 22 12 C19 17 15.5 19 12 19 C8.5 19 5 17 2 12 Z" fill={accent} stroke="none" />}
        <path d="M2 12 C5 7 8.5 5 12 5 C15.5 5 19 7 22 12 C19 17 15.5 19 12 19 C8.5 19 5 17 2 12 Z" fill={style === 'filled' ? fill : 'none'} />
        <circle cx="12" cy="12" r="3" fill={style === 'filled' ? '#1A1F12' : 'none'} />
      </>
    );
  },
  Rating: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M12 3 L14.5 9 L21 9.5 L16 13.5 L17.5 20 L12 16.5 L6.5 20 L8 13.5 L3 9.5 L9.5 9 Z" fill={accent} stroke="none" />}
        <path d="M12 3 L14.5 9 L21 9.5 L16 13.5 L17.5 20 L12 16.5 L6.5 20 L8 13.5 L3 9.5 L9.5 9 Z" fill={style === 'filled' ? fill : 'none'} />
      </>
    );
  },
  Language: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <circle cx="12" cy="12" r="9" fill={accent} stroke="none" />}
        <circle cx="12" cy="12" r="9" fill={style === 'filled' ? fill : 'none'} />
        <path d="M3 12 H21" stroke={style === 'filled' ? '#1A1F12' : stroke} />
        <path d="M12 3 C8.5 7 8.5 17 12 21 M12 3 C15.5 7 15.5 17 12 21" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  SubtitlesM: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <path d="M3 4 H21 V18 H14 L11 22 L8 18 H3 Z" fill={accent} stroke="none" />}
        <path d="M3 4 H21 V18 H14 L11 22 L8 18 H3 Z" fill={style === 'filled' ? fill : 'none'} />
        <path d="M6 9 H12 M14 9 H18 M6 13 H10 M12 13 H18" stroke={style === 'filled' ? '#1A1F12' : stroke} />
      </>
    );
  },
  AgeRating: ({ style, stroke, sage }) => {
    const { fill, accent } = f(style, stroke, sage);
    return (
      <>
        {style === 'duotone' && <rect x="3" y="3" width="18" height="18" rx="3" fill={accent} stroke="none" />}
        <rect x="3" y="3" width="18" height="18" rx="3" fill={style === 'filled' ? fill : 'none'} />
        <path d="M8 16 V8 H10 L11.5 12 L13 8 H15 V16" stroke={style === 'filled' ? '#1A1F12' : stroke} fill="none" strokeWidth={1.8} />
      </>
    );
  },
};

window.AYA_ICONS_B = { ACTIONS, CREW, ROLES, META };
